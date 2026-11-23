using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Theme = PacketTrace.DesktopTheme;

namespace PacketTrace
{
    sealed partial class MainWindow
    {
        readonly ComboBox adapters = Combo(243, "网卡"), protocols = Combo(112, "显示协议");
        readonly ActionButton open = new ActionButton("打开 PCAP", 113, "open"),
            save = new ActionButton("保存 PCAP", 109),
            refresh = new ActionButton("", 33, "refresh") { AccessibleName = "刷新网卡" },
            start = new ActionButton("开始抓包", 112, "start", true),
            stop = new ActionButton("停止", 77, "stop"),
            demo = new ActionButton("本机网页演示", 139, "demo"),
            resetFilter = new ActionButton("重置", 63),
            clear = new ActionButton("清空列表", 89),
            isolate = new ActionButton("仅看本连接", 118, "filter");
        readonly TextBox search = new TextBox { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None,
            Font = Theme.Ui, ForeColor = Theme.Ink, BackColor = Color.White,
            AccessibleName = "按 IP 地址或端口筛选" };
        readonly Label message = Theme.Label("", Theme.Muted),
            counters = Theme.Label("", Theme.Ink),
            sourceLabel = Theme.Label("尚未选择抓包来源", Theme.Muted),
            activeFlow = Theme.Label("", Theme.Blue, Theme.UiBold),
            outcome = Theme.Label("", Theme.Ink, Theme.UiBold),
            flowMeta = Theme.Label("", Theme.Muted);
        readonly Label captureStatus = new CaptureBadge { Text = "就绪", AccessibleName = "抓包状态",
            BackColor = Color.FromArgb(41, 60, 86), Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 14) };
        readonly DataGridView packets = Grid("数据包列表"), timeline = Grid("TCP 连接时序");
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill, DrawMode = TabDrawMode.OwnerDrawFixed,
            SizeMode = TabSizeMode.Fixed, ItemSize = new Size(132, 34), Font = Theme.UiBold };
        readonly TabPage flowTab = new TabPage("TCP 连接");
        readonly PacketInspector inspector = new PacketInspector();
        readonly ToolTip tips = new ToolTip();
        readonly ContextMenuStrip packetMenu = new ContextMenuStrip();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, string text);

        void BuildLayout()
        {
            SuspendLayout();
            Text = "PacketTrace · 网络数据包分析";
            BackColor = Theme.Canvas;
            ForeColor = Theme.Ink;
            Font = Theme.Ui;
            AutoScaleDimensions = new SizeF(96, 96);
            AutoScaleMode = AutoScaleMode.Dpi;
            MinimumSize = new Size(985, 680);
            Size = new Size(1270, 840);
            StartPosition = FormStartPosition.CenterScreen;
            DoubleBuffered = true;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Margin = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 61));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 53));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            root.Controls.Add(BuildHeader(), 0, 0);
            root.Controls.Add(BuildToolbar(), 0, 1);
            root.Controls.Add(BuildFilters(), 0, 2);
            root.Controls.Add(BuildWorkspace(), 0, 3);
            root.Controls.Add(BuildStatusBar(), 0, 4);
            Controls.Add(root);

            tips.SetToolTip(open, "打开抓包文件（Ctrl+O）");
            tips.SetToolTip(save, "保存当前保留的全部报文（Ctrl+S）");
            tips.SetToolTip(start, "开始抓包（F5）");
            tips.SetToolTip(stop, "停止抓包（Shift+F5）");
            tips.SetToolTip(refresh, "刷新网卡");
            tips.SetToolTip(search, "按 IP 或端口筛选（Ctrl+F）");
            tips.SetToolTip(demo, "在本机回环上演示 HTTP 200、HTTP 404 和连接被拒绝");
            tips.SetToolTip(isolate, "在上方列表中显示这条连接的所有包");
            tips.SetToolTip(timeline, "双击一行可在上方定位对应的数据包");
            search.HandleCreated += (sender, e) => SendMessage(search.Handle, 0x1501, IntPtr.Zero, "输入 IP 地址或端口");

            var track = packetMenu.Items.Add("查看 TCP 连接");
            var only = packetMenu.Items.Add("仅看本连接");
            packetMenu.Opening += (sender, e) => e.Cancel = selected == null || selected.Flow == null;
            track.Click += (sender, e) => tabs.SelectedTab = flowTab;
            only.Click += (sender, e) => { if (selected != null && selected.Flow != null) SetFlowFilter(selected.Flow); };
            packets.ContextMenuStrip = packetMenu;
            packets.CellMouseDown += (sender, e) =>
            {
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && e.RowIndex < packets.RowCount)
                    packets.CurrentCell = packets.Rows[e.RowIndex].Cells[0];
            };
            ResumeLayout(true);
        }

        Control BuildHeader()
        {
            var bar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
                BackColor = Theme.Navy, Margin = Padding.Empty, Padding = new Padding(18, 0, 18, 0) };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 47));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
            bar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var logo = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 10, 0) };
            logo.Paint += (sender, e) =>
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                int size = Math.Min(logo.Width - 2, logo.Height - 10);
                if (size < 16) return;
                var box = new Rectangle(0, (logo.Height - size) / 2, size, size);
                using (var path = Theme.Rounded(box, 7))
                using (var blue = new SolidBrush(Color.FromArgb(52, 106, 220)))
                    e.Graphics.FillPath(blue, path);
                Theme.Glyph(e.Graphics, "trace", Rectangle.Inflate(box, -7, -7), Color.White);
            };
            var title = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight,
                Padding = new Padding(0, 13, 0, 0), Margin = Padding.Empty, WrapContents = false };
            title.Controls.Add(new Label { Text = "PacketTrace", AutoSize = true, ForeColor = Color.White,
                Font = new Font("Segoe UI", 19F, FontStyle.Bold), Margin = new Padding(0, 0, 15, 0) });
            title.Controls.Add(new Label { Text = "网络数据包分析", AutoSize = true, ForeColor = Color.FromArgb(174, 195, 221),
                Font = Theme.Ui, Margin = new Padding(0, 11, 0, 0) });
            bar.Controls.Add(logo, 0, 0);
            bar.Controls.Add(title, 1, 0);
            bar.Controls.Add(captureStatus, 2, 0);
            return bar;
        }

        Control BuildToolbar()
        {
            var bar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
                Margin = Padding.Empty, BackColor = Color.White, Padding = new Padding(16, 10, 10, 8) };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var commands = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.White, WrapContents = false, Margin = Padding.Empty };
            commands.Controls.Add(open);
            commands.Controls.Add(save);
            commands.Controls.Add(new Panel { BackColor = Theme.Line, Width = 1, Height = 25, Margin = new Padding(6, 4, 15, 0) });
            commands.Controls.Add(new Label { Text = "网卡", AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(0, 8, 8, 0) });
            adapters.Margin = new Padding(0, 3, 7, 0);
            commands.Controls.AddRange(new Control[] { adapters, refresh, start, stop });
            bar.Controls.Add(commands, 0, 0);
            bar.Controls.Add(demo, 1, 0);
            return bar;
        }

        Control BuildFilters()
        {
            var bar = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Theme.Pale, ColumnCount = 5, RowCount = 1,
                Margin = Padding.Empty, Padding = new Padding(16, 7, 9, 7) };
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 126));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var title = Theme.Label("显示筛选", Theme.Ink, Theme.UiBold);
            title.Padding = new Padding(24, 0, 0, 0);
            title.Paint += (sender, e) => Theme.Glyph(e.Graphics, "filter",
                new Rectangle(0, (title.Height - 15) / 2, 15, 15), Theme.Blue);
            protocols.Items.AddRange(new object[] { "全部协议", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP" });
            protocols.SelectedIndex = 0;
            protocols.Margin = new Padding(0, 4, 8, 0);
            protocols.Dock = DockStyle.Top;
            var field = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 1, 8, 2), Padding = new Padding(31, 6, 5, 3) };
            field.Paint += (sender, e) => Theme.Glyph(e.Graphics, "search",
                new Rectangle(8, (field.ClientSize.Height - 15) / 2, 15, 15), Theme.Muted);
            field.Controls.Add(search);
            field.Click += (sender, e) => search.Focus();
            activeFlow.Padding = new Padding(7, 0, 2, 0);
            activeFlow.AutoSize = true;
            bar.Controls.Add(title, 0, 0);
            bar.Controls.Add(protocols, 1, 0);
            bar.Controls.Add(field, 2, 0);
            bar.Controls.Add(activeFlow, 3, 0);
            bar.Controls.Add(resetFilter, 4, 0);
            return bar;
        }

        Control BuildWorkspace()
        {
            var body = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = Theme.Canvas,
                Margin = new Padding(15, 9, 15, 0), SplitterWidth = 9, Size = new Size(1220, 610) };
            body.Panel1MinSize = 175;
            body.Panel2MinSize = 190;
            body.SplitterDistance = 305;

            var packetPane = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1, BackColor = Color.White };
            packetPane.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
            packetPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var packetHead = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1,
                BackColor = Color.White, Padding = new Padding(12, 5, 5, 4), Margin = Padding.Empty };
            packetHead.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 122));
            packetHead.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            packetHead.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            packetHead.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var listTitle = Theme.Label("数据包列表", Theme.Ink, Theme.UiBold);
            listTitle.Padding = new Padding(25, 0, 0, 0);
            listTitle.Paint += (sender, e) => Theme.Glyph(e.Graphics, "list",
                new Rectangle(0, (listTitle.Height - 16) / 2, 16, 16), Theme.Blue);
            sourceLabel.TextAlign = ContentAlignment.MiddleRight;
            sourceLabel.Padding = new Padding(0, 0, 13, 0);
            packetHead.Controls.Add(listTitle, 0, 0);
            packetHead.Controls.Add(sourceLabel, 1, 0);
            packetHead.Controls.Add(clear, 2, 0);
            packetPane.Controls.Add(packetHead, 0, 0);
            packetPane.Controls.Add(packets, 0, 1);
            body.Panel1.Controls.Add(packetPane);

            AddColumn(packets, "编号", 61, mono: true);
            AddColumn(packets, "时间", 118, mono: true);
            AddColumn(packets, "源地址", 174, mono: true);
            AddColumn(packets, "目标地址", 174, mono: true);
            AddColumn(packets, "协议", 79);
            AddColumn(packets, "长度", 66, mono: true, numeric: true);
            AddColumn(packets, "摘要", 250, fill: true);
            packets.Paint += PaintEmptyPackets;
            packets.CellPainting += PaintProtocol;
            packets.CellFormatting += (sender, e) =>
            {
                if (e.RowIndex < 0 || e.RowIndex >= visible.Count || e.ColumnIndex != 6) return;
                Packet p = visible[e.RowIndex];
                if (p.Reset || p.HttpStatus >= 500) e.CellStyle.ForeColor = Theme.Red;
                else if (p.HttpStatus >= 400) e.CellStyle.ForeColor = Theme.Amber;
            };

            tabs.TabPages.Add(new TabPage("数据包详情") { BackColor = Theme.Canvas, Controls = { inspector } });
            tabs.TabPages.Add(flowTab);
            tabs.DrawItem += DrawTab;
            flowTab.BackColor = Color.White;
            flowTab.Controls.Add(BuildFlowPane());
            body.Panel2.Controls.Add(tabs);
            return body;
        }

        Control BuildFlowPane()
        {
            var flow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Color.White };
            flow.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));
            flow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2,
                BackColor = Theme.Pale, Margin = Padding.Empty, Padding = new Padding(12, 7, 6, 7) };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            header.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            isolate.Anchor = AnchorStyles.Right;
            header.Controls.Add(outcome, 0, 0);
            header.Controls.Add(flowMeta, 0, 1);
            header.Controls.Add(isolate, 1, 0);
            header.SetRowSpan(isolate, 2);
            flow.Controls.Add(header, 0, 0);
            flow.Controls.Add(timeline, 0, 1);
            AddColumn(timeline, "帧编号", 69, mono: true);
            AddColumn(timeline, "相对时间", 120, mono: true);
            AddColumn(timeline, "方向", 151);
            AddColumn(timeline, "TCP 标志", 140, mono: true);
            AddColumn(timeline, "事件 / 摘要", 260, fill: true);
            timeline.CellFormatting += (sender, e) =>
            {
                if (e.RowIndex < 0 || e.RowIndex >= flowRows.Count) return;
                Packet p = flowRows[e.RowIndex];
                if (e.ColumnIndex == 2)
                    e.CellStyle.ForeColor = p.Endpoint(true) == p.Flow.Client ? Theme.Blue : Theme.Teal;
                if (e.ColumnIndex == 3 && p.Reset) e.CellStyle.ForeColor = Theme.Red;
                if (e.ColumnIndex == 4 && p.HttpStatus >= 400) e.CellStyle.ForeColor = Theme.Amber;
                if (e.ColumnIndex == 4 && p.Reset) e.CellStyle.ForeColor = Theme.Red;
            };
            return flow;
        }

        Control BuildStatusBar()
        {
            var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
                Margin = Padding.Empty, Padding = new Padding(16, 0, 16, 0), BackColor = Theme.Canvas };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            counters.AutoSize = true;
            counters.Padding = new Padding(13, 0, 0, 0);
            counters.TextAlign = ContentAlignment.MiddleRight;
            footer.Controls.Add(message, 0, 0);
            footer.Controls.Add(counters, 1, 0);
            return footer;
        }

        void DrawTab(object sender, DrawItemEventArgs e)
        {
            bool selectedTab = e.Index == tabs.SelectedIndex;
            using (var fill = new SolidBrush(selectedTab ? Color.White : Theme.Pale))
            using (var line = new SolidBrush(Theme.Blue))
            {
                e.Graphics.FillRectangle(fill, e.Bounds);
                if (selectedTab) e.Graphics.FillRectangle(line, e.Bounds.Left, e.Bounds.Bottom - 2, e.Bounds.Width, 2);
            }
            TextRenderer.DrawText(e.Graphics, tabs.TabPages[e.Index].Text, tabs.Font, e.Bounds,
                selectedTab ? Theme.Blue : Theme.Muted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }

        void PaintEmptyPackets(object sender, PaintEventArgs e)
        {
            if (visible.Count != 0) return;
            string headline = all.Count > 0 ? "没有符合筛选条件的数据包" : "暂无数据包";
            string hint = all.Count > 0 ? "调整筛选条件，或点「重置」" :
                session != null && session.Live ? "等待来自当前网卡的流量" : "选择网卡开始抓包，或打开 PCAP 文件";
            int middle = packets.ColumnHeadersHeight + (packets.Height - packets.ColumnHeadersHeight) / 2;
            var icon = new Rectangle((packets.Width - 34) / 2, middle - 35, 34, 34);
            using (var brush = new SolidBrush(Theme.Selected))
                e.Graphics.FillEllipse(brush, icon);
            Theme.Glyph(e.Graphics, "list", Rectangle.Inflate(icon, -8, -8), Theme.Blue);
            const TextFormatFlags centered = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine;
            TextRenderer.DrawText(e.Graphics, headline, Theme.UiBold, new Rectangle(0, middle + 2, packets.Width, 24), Theme.Ink, centered);
            TextRenderer.DrawText(e.Graphics, hint, Theme.Ui, new Rectangle(0, middle + 25, packets.Width, 22), Theme.Muted, centered);
        }

        void PaintProtocol(object sender, DataGridViewCellPaintingEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex != 4 || e.RowIndex >= visible.Count) return;
            Packet p = visible[e.RowIndex];
            string name = p.Protocol;
            Color text;
            Color fill;
            switch (name)
            {
                case "HTTP":
                    text = Theme.Teal; fill = Color.FromArgb(222, 244, 235); break;
                case "TCP":
                    text = Theme.Blue; fill = Color.FromArgb(229, 238, 255); break;
                case "UDP":
                    text = Color.FromArgb(105, 64, 155); fill = Color.FromArgb(239, 231, 251); break;
                case "ICMP":
                case "ICMPv6":
                    text = Theme.Amber; fill = Color.FromArgb(255, 239, 214); break;
                default:
                    text = Theme.Muted; fill = Color.FromArgb(233, 239, 245); break;
            }
            e.PaintBackground(e.ClipBounds, true);
            var rect = new Rectangle(e.CellBounds.X + 8, e.CellBounds.Y + 5, e.CellBounds.Width - 16, e.CellBounds.Height - 10);
            if (rect.Width > 8 && rect.Height >= 8)
            {
                GraphicsState saved = e.Graphics.Save();
                e.Graphics.SetClip(e.CellBounds, CombineMode.Intersect);
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using (var shape = Theme.Rounded(rect, 4))
                using (var brush = new SolidBrush(fill))
                    e.Graphics.FillPath(brush, shape);
                TextRenderer.DrawText(e.Graphics, name, Theme.UiBold, rect, text,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
                e.Graphics.Restore(saved);
            }
            e.Handled = true;
        }

        static ComboBox Combo(int width, string label)
        {
            return new ComboBox { Width = width, DropDownWidth = width + 100, DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Flat, Font = Theme.Ui, BackColor = Color.White, ForeColor = Theme.Ink,
                AccessibleName = label };
        }

        static DataGridView Grid(string name)
        {
            var g = new DataGridView
            {
                AccessibleName = name, VirtualMode = true, Dock = DockStyle.Fill, Margin = Padding.Empty,
                BackgroundColor = Color.White, BorderStyle = BorderStyle.None, ReadOnly = true, RowHeadersVisible = false,
                MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect, AllowUserToAddRows = false,
                AllowUserToDeleteRows = false, AllowUserToResizeRows = false, AutoGenerateColumns = false,
                GridColor = Theme.Line, CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None, EnableHeadersVisualStyles = false,
                ColumnHeadersHeight = 35, ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing
            };
            g.RowTemplate.Height = 28;
            g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(236, 242, 249),
                ForeColor = Theme.Muted, Font = Theme.UiBold, Padding = new Padding(7, 0, 5, 0),
                SelectionBackColor = Color.FromArgb(236, 242, 249), SelectionForeColor = Theme.Muted };
            g.DefaultCellStyle = new DataGridViewCellStyle { Font = Theme.Ui, BackColor = Color.White,
                ForeColor = Theme.Ink, Padding = new Padding(7, 0, 4, 0),
                SelectionBackColor = Theme.Selected, SelectionForeColor = Theme.Ink,
                WrapMode = DataGridViewTriState.False };
            g.AlternatingRowsDefaultCellStyle.BackColor = Theme.Pale;
            return g;
        }

        static void AddColumn(DataGridView grid, string title, int width, bool fill = false, bool mono = false, bool numeric = false)
        {
            var column = new DataGridViewTextBoxColumn { HeaderText = title, Width = width, MinimumWidth = fill ? 142 : 52,
                SortMode = DataGridViewColumnSortMode.NotSortable, AutoSizeMode = fill ? DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.None };
            if (mono) column.DefaultCellStyle.Font = Theme.Mono;
            if (numeric)
            {
                column.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
                column.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight;
            }
            grid.Columns.Add(column);
        }
    }
}
