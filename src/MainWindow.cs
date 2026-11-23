using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Theme = PacketTrace.DesktopTheme;

namespace PacketTrace
{
    sealed partial class MainWindow : Form
    {
        const int History = 3000;
        const int HistoryBytes = 32 * 1024 * 1024;
        const int QueueBytes = 16 * 1024 * 1024;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 80 };
        readonly List<Packet> all = new List<Packet>(), visible = new List<Packet>(), flowRows = new List<Packet>();
        TcpFlows flows = new TcpFlows();
        TcpFlow flowFilter;
        Session session;
        int number, dropped, evicted, retainedBytes;
        bool changingRows, demoRunning;
        Packet selected;

        sealed class Session
        {
            public readonly CancellationTokenSource Stop = new CancellationTokenSource();
            public readonly ConcurrentQueue<Packet> Queue = new ConcurrentQueue<Packet>();
            public bool Live, Loopback;
            public volatile bool Ready, Done;
            public volatile string Error;
            public int Waiting, WaitingBytes, Dropped;
        }

        public MainWindow(string initialFile)
        {
            BuildLayout();

            packets.CellValueNeeded += PacketValue;
            timeline.CellValueNeeded += FlowValue;
            packets.CurrentCellChanged += (sender, e) => SelectPacket();
            packets.CellDoubleClick += (sender, e) => { if (e.RowIndex >= 0 && selected != null && selected.Flow != null) tabs.SelectedTab = flowTab; };
            timeline.CellDoubleClick += (sender, e) =>
            {
                if (e.RowIndex < 0 || e.RowIndex >= flowRows.Count) return;
                Packet target = flowRows[e.RowIndex];
                if (!visible.Contains(target)) SetFlowFilter(target.Flow);
                int row = visible.IndexOf(target);
                if (row >= 0) packets.CurrentCell = packets.Rows[row].Cells[0];
            };
            tabs.SelectedIndexChanged += (sender, e) => UpdateDetails();
            protocols.SelectedIndexChanged += (sender, e) => Refilter();
            search.TextChanged += (sender, e) => Refilter();
            adapters.SelectedIndexChanged += (sender, e) => Buttons();
            refresh.Click += (sender, e) => RefreshAdapters();
            start.Click += (sender, e) => Begin((Adapter)adapters.SelectedItem, null);
            stop.Click += (sender, e) => StopCapture();
            open.Click += (sender, e) => OpenFile();
            save.Click += (sender, e) => SaveFile();
            clear.Click += (sender, e) => { Reset(); if (session != null) dropped = session.Dropped; };
            resetFilter.Click += (sender, e) => ResetFilters();
            isolate.Click += (sender, e) => SetFlowFilter(flowFilter != null ? null : selected == null ? null : selected.Flow);
            demo.Click += async (sender, e) => await RunDemo();
            timer.Tick += (sender, e) => Drain();
            FormClosing += (sender, e) => { timer.Stop(); if (session != null) session.Stop.Cancel(); };
            FormClosed += (sender, e) => { timer.Dispose(); tips.Dispose(); packetMenu.Dispose(); };
            Shown += (sender, e) =>
            {
                RefreshAdapters();
                if (!string.IsNullOrEmpty(initialFile)) Begin(null, initialFile);
                timer.Start();
            };
            Reset();
            Buttons();
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keys)
        {
            if (keys == (Keys.Control | Keys.O) && open.Enabled) { OpenFile(); return true; }
            if (keys == (Keys.Control | Keys.S) && save.Enabled) { SaveFile(); return true; }
            if (keys == (Keys.Control | Keys.F) && search.Enabled)
            {
                search.Focus();
                search.SelectAll();
                return true;
            }
            if (keys == Keys.F5 && start.Enabled) { start.PerformClick(); return true; }
            if (keys == (Keys.Shift | Keys.F5) && stop.Enabled) { StopCapture(); return true; }
            return base.ProcessCmdKey(ref msg, keys);
        }

        void StopCapture()
        {
            if (session == null) return;
            session.Stop.Cancel();
            message.Text = "正在停止…";
            SetStatus("正在停止", Color.FromArgb(83, 100, 124));
            Buttons();
        }

        void SetStatus(string text, Color background)
        {
            captureStatus.Text = text;
            captureStatus.BackColor = background;
        }

        void RefreshAdapters()
        {
            var previous = adapters.SelectedItem as Adapter;
            adapters.Items.Clear();
            try
            {
                List<Adapter> list = PacketTrace.Capture.Adapters();
                foreach (Adapter a in list) adapters.Items.Add(a);
                var pick = list.Find(a => previous != null && a.Name == previous.Name) ??
                    list.Find(a => !a.Loopback && a.Connected) ?? list.Find(a => a.Loopback) ?? list.Find(a => !a.Loopback);
                if (pick != null) adapters.SelectedItem = pick;
                message.Text = pick != null ? "选择网卡后开始抓包。本机网页演示请选择回环网卡。" : "没有可用网卡。请检查 Npcap 与抓包权限。";
            }
            catch (Exception ex) { message.Text = ex.GetBaseException().Message; }
            Buttons();
        }

        void OpenFile()
        {
            using (var dialog = new OpenFileDialog { Filter = "PCAP 抓包文件 (*.pcap)|*.pcap", Title = "打开抓包文件" })
                if (dialog.ShowDialog(this) == DialogResult.OK) Begin(null, dialog.FileName);
        }

        void SaveFile()
        {
            if (session != null || all.Count == 0) return;
            using (var dialog = new SaveFileDialog
            {
                Filter = "PCAP 抓包文件 (*.pcap)|*.pcap", Title = "保存当前保留的全部报文",
                DefaultExt = "pcap", AddExtension = true, OverwritePrompt = true, RestoreDirectory = true,
                FileName = "PacketTrace-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".pcap"
            })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    SaveRetainedPackets(dialog.FileName);
                    message.Text = "已保存 " + all.Count + " 个包：" + Path.GetFileName(dialog.FileName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.GetBaseException().Message, "保存失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        void SaveRetainedPackets(string path)
        {
            PacketTrace.Capture.WriteFile(path, all.ConvertAll(p => p.RawFrame));
        }

        void Begin(Adapter adapter, string path)
        {
            if (session != null || (adapter == null && path == null)) return;
            Reset();
            ResetFilters();
            var state = new Session { Live = adapter != null, Loopback = adapter != null && adapter.Loopback };
            session = state;
            Buttons();
            sourceLabel.Text = state.Live ? "网卡  /  " + adapter.Label : "文件  /  " + Path.GetFileName(path);
            tips.SetToolTip(sourceLabel, state.Live ? adapter.Label : path);
            SetStatus(state.Live ? "正在连接" : "正在读取", Theme.Blue);
            message.Text = state.Live ? "正在打开网卡…" : "正在读取 " + Path.GetFileName(path) + "…";
            Task.Run(() =>
            {
                Action<Frame> receive = frame =>
                {
                    int size = frame.Bytes.Length;
                    while (!state.Stop.IsCancellationRequested &&
                        (Volatile.Read(ref state.Waiting) >= 1200 || Volatile.Read(ref state.WaitingBytes) + size > QueueBytes))
                    {
                        if (state.Live)
                        {
                            Interlocked.Increment(ref state.Dropped);
                            return;
                        }
                        Thread.Sleep(12);
                    }
                    if (state.Stop.IsCancellationRequested) return;
                    Packet parsed = PacketParser.Parse(frame.Bytes, frame.LinkType, frame.Time, frame.Length);
                    parsed.RawFrame = frame;
                    Interlocked.Increment(ref state.Waiting);
                    Interlocked.Add(ref state.WaitingBytes, size);
                    state.Queue.Enqueue(parsed);
                };
                try
                {
                    if (state.Live) PacketTrace.Capture.ReadLive(adapter, state.Stop.Token, _ => state.Ready = true, receive);
                    else PacketTrace.Capture.ReadFile(path, state.Stop.Token, receive);
                }
                catch (Exception ex) { state.Error = ex.GetBaseException().Message; }
                finally { state.Done = true; }
            });
        }

        async Task RunDemo()
        {
            if (demoRunning || session == null || !session.Loopback || !session.Ready) return;
            Session state = session;
            demoRunning = true;
            Buttons();
            message.Text = "正在访问本机网页…";
            try
            {
                int port = await Task.Run(() => Demo.Run());
                if (session != state) return;
                ResetFilters();
                search.Text = port.ToString();
                tabs.SelectedTab = flowTab;
                Drain();
                for (int attempt = 0; session == state && !HasDemoResults(port) && attempt < 20; attempt++)
                    await Task.Delay(80);
                if (session == state)
                    message.Text = HasDemoResults(port)
                        ? "演示端口 " + port + "  ·  点选不同连接中的包，查看 200、404 和连接被拒绝。"
                        : "网页访问已执行，但抓包结果不完整。请重试本机网页演示。";
            }
            catch (Exception ex) { message.Text = "演示失败：" + ex.GetBaseException().Message; }
            finally { demoRunning = false; Buttons(); }
        }

        bool HasDemoResults(int port)
        {
            bool ok = false, missing = false, refused = false;
            foreach (Packet p in all)
            {
                if (p.Flow == null || (p.SourcePort != port && p.DestinationPort != port) ||
                    p.Source != "127.0.0.1" || p.Destination != "127.0.0.1") continue;
                ok |= p.HttpStatus == 200;
                missing |= p.HttpStatus == 404;
                refused |= p.Reset && p.Flow.Refused;
                if (ok && missing && refused) return true;
            }
            return false;
        }

        void Drain()
        {
            Session state = session;
            if (state == null) return;
            if (state.Ready && state.Live && message.Text == "正在打开网卡…")
            {
                message.Text = state.Loopback ? "正在抓取本机回环流量。可以点「本机网页演示」。" : "正在抓包。双击 TCP 包可查看连接。";
                SetStatus("实时抓包", Theme.Teal);
                Buttons();
            }
            string protocol = (string)protocols.SelectedItem;
            string term = search.Text.Trim();
            int count = 0;
            Packet packet;
            while (count < 480 && state.Queue.TryDequeue(out packet))
            {
                Interlocked.Decrement(ref state.Waiting);
                Interlocked.Add(ref state.WaitingBytes, -packet.CapturedLength);
                packet.Number = ++number;
                flows.Add(packet);
                all.Add(packet);
                retainedBytes += packet.CapturedLength;
                if (MatchesDisplay(packet, protocol, term)) visible.Add(packet);
                count++;
            }
            dropped = state.Dropped;
            if (all.Count > History || retainedBytes > HistoryBytes)
            {
                int remove = 0;
                while (all.Count - remove > History || retainedBytes > HistoryBytes)
                    retainedBytes -= all[remove++].CapturedLength;
                all.RemoveRange(0, remove);
                evicted += remove;
                flows.Prune(all[0].Number);
                if (flowFilter != null && flowFilter.LastPacket < all[0].Number) flowFilter = null;
                Refilter();
            }
            else if (count > 0)
            {
                UpdateRows();
                if (tabs.SelectedTab == flowTab) UpdateDetails();
            }
            if (state.Done && state.Queue.IsEmpty)
            {
                message.Text = state.Error != null ? "读取失败：" + state.Error :
                    state.Stop.IsCancellationRequested ? "已停止。可以继续查看已捕获的数据包。" : "已打开抓包文件。双击 TCP 包可查看连接。";
                if (state.Error != null) SetStatus("读取失败", Theme.Red);
                else if (state.Stop.IsCancellationRequested) SetStatus("已停止", Color.FromArgb(62, 82, 109));
                else SetStatus("离线分析", Theme.Blue);
                state.Stop.Dispose();
                session = null;
                Buttons();
            }
            Counts();
        }

        void Buttons()
        {
            bool idle = session == null;
            start.Enabled = idle && adapters.SelectedItem != null;
            stop.Enabled = !idle && !session.Stop.IsCancellationRequested && !demoRunning;
            refresh.Enabled = open.Enabled = adapters.Enabled = idle;
            save.Enabled = idle && all.Count > 0;
            demo.Enabled = !idle && session.Loopback && session.Ready && !session.Stop.IsCancellationRequested && !demoRunning;
        }

        void Reset()
        {
            all.Clear();
            visible.Clear();
            flows = new TcpFlows();
            flowFilter = null;
            number = evicted = retainedBytes = 0;
            if (session == null) dropped = 0;
            selected = null;
            UpdateRows();
            UpdateDetails();
            Counts();
            UpdateFilterControls();
        }

        bool MatchesDisplay(Packet packet, string protocol, string term)
        {
            return flowFilter != null ? packet.Flow == flowFilter : packet.Matches(protocol, term);
        }

        void ResetFilters()
        {
            flowFilter = null;
            protocols.SelectedIndex = 0;
            search.Clear();
            Refilter();
        }

        void SetFlowFilter(TcpFlow flow)
        {
            flowFilter = flow;
            if (flow != null) tabs.SelectedTab = flowTab;
            Refilter();
        }

        void UpdateFilterControls()
        {
            protocols.Enabled = search.Enabled = flowFilter == null;
            activeFlow.Text = flowFilter == null ? "" : "TCP 连接  #" + flowFilter.FirstPacket;
            activeFlow.Visible = flowFilter != null;
            resetFilter.Enabled = flowFilter != null || protocols.SelectedIndex > 0 || search.Text.Length > 0;
        }

        void Refilter()
        {
            string protocol = (string)protocols.SelectedItem;
            string term = search.Text.Trim();
            visible.Clear();
            foreach (Packet p in all)
                if (MatchesDisplay(p, protocol, term)) visible.Add(p);
            UpdateRows();
            UpdateDetails();
            Counts();
            UpdateFilterControls();
        }

        void UpdateRows()
        {
            changingRows = true;
            try
            {
                if (packets.RowCount != visible.Count) packets.RowCount = visible.Count;
                int target = selected != null ? visible.IndexOf(selected) : -1;
                if (target < 0 && visible.Count > 0) target = 0;
                if (target >= 0 && (packets.CurrentCell == null || packets.CurrentCell.RowIndex != target))
                    packets.CurrentCell = packets.Rows[target].Cells[0];
                packets.Invalidate();
            }
            finally { changingRows = false; }
            SelectPacket();
        }

        void SelectPacket()
        {
            if (changingRows) return;
            int index = packets.CurrentCell == null ? -1 : packets.CurrentCell.RowIndex;
            Packet p = index >= 0 && index < visible.Count ? visible[index] : null;
            if (selected == p) return;
            selected = p;
            UpdateDetails();
        }

        void UpdateDetails()
        {
            if (tabs.SelectedTab != flowTab)
            {
                inspector.ShowPacket(selected);
                return;
            }
            TcpFlow flow = selected == null ? null : selected.Flow;
            flowRows.Clear();
            if (flow != null)
                foreach (Packet p in all)
                    if (p.Flow == flow) flowRows.Add(p);
            if (timeline.RowCount != flowRows.Count) timeline.RowCount = flowRows.Count;
            timeline.Invalidate();
            isolate.Text = flowFilter != null ? "退出连接筛选" : "仅看本连接";
            isolate.Enabled = flowRows.Count != 0 || flowFilter != null;
            if (flowRows.Count == 0)
            {
                outcome.ForeColor = Theme.Muted;
                outcome.Text = "选择一个 TCP 数据包";
                flowMeta.Text = "此处会显示连接的双向时序。";
                return;
            }
            int status = selected.HttpStatus != 0 ? selected.HttpStatus : flow.HttpStatus;
            outcome.ForeColor = status >= 500 || (status == 0 && flow.Refused) ? Theme.Red :
                status >= 400 ? Theme.Amber : status >= 200 && status < 300 ? Theme.Teal : Theme.Blue;
            outcome.Text = flow.OutcomeFor(selected);
            flowMeta.Text = flow.Client + "  ↔  " + flow.Server + "   ·   " + flowRows.Count + " 个包" +
                (flowRows[0].Number != flow.FirstPacket ? "（开头已移出列表）" : "");
        }

        void Counts()
        {
            counters.Text = "显示 " + visible.Count + " / 保留 " + all.Count +
                (evicted > 0 ? "  ·  已移出 " + evicted : "") + (dropped > 0 ? "  ·  未处理 " + dropped : "");
            clear.Enabled = all.Count > 0;
            save.Enabled = session == null && all.Count > 0;
        }

        void PacketValue(object sender, DataGridViewCellValueEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= visible.Count) return;
            Packet p = visible[e.RowIndex];
            switch (e.ColumnIndex)
            {
                case 0: e.Value = p.Number; break;
                case 1: e.Value = p.Time.ToString("HH:mm:ss.fff"); break;
                case 2: e.Value = p.Endpoint(true); break;
                case 3: e.Value = p.Endpoint(false); break;
                case 4: e.Value = p.Protocol; break;
                case 5: e.Value = p.Length; break;
                case 6: e.Value = p.Summary; break;
            }
        }

        void FlowValue(object sender, DataGridViewCellValueEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= flowRows.Count) return;
            Packet p = flowRows[e.RowIndex];
            switch (e.ColumnIndex)
            {
                case 0: e.Value = p.Number; break;
                case 1: e.Value = (p.Time - p.Flow.Started).TotalMilliseconds.ToString("0.000") + " ms"; break;
                case 2:
                    bool forward = p.Endpoint(true) == p.Flow.Client;
                    e.Value = p.Flow.KnowsInitiator
                        ? (forward ? "发起方 → 对端" : "对端 → 发起方")
                        : (forward ? "A → B" : "B → A");
                    break;
                case 3: e.Value = p.FlagNames(); break;
                case 4:
                    string sequence = "Seq " + p.Seq + "  ·  Ack " + p.Ack;
                    if (p.HttpLine != null) e.Value = p.HttpLine;
                    else if (p.Reset) e.Value = (p.Flow.Refused ? "拒绝连接" : "重置连接") + "  ·  " + sequence;
                    else if (p.Syn) e.Value = (p.AckFlag ? "确认连接请求" : "发起连接") + "  ·  " + sequence;
                    else if (p.Fin) e.Value = "结束发送  ·  " + sequence;
                    else e.Value = sequence + (p.PayloadLength > 0 ? "  ·  " + p.PayloadLength + " B 数据" : "");
                    break;
            }
        }

    }
}
