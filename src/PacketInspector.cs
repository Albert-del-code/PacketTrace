using System;
using System.Drawing;
using System.Windows.Forms;

namespace PacketTrace
{
    sealed class PacketInspector : UserControl
    {
        readonly Label frameTitle = DesktopTheme.Label("协议层级", DesktopTheme.Ink, DesktopTheme.UiBold);
        readonly Label byteTitle = DesktopTheme.Label("原始字节", DesktopTheme.Ink, DesktopTheme.UiBold);
        readonly TreeView layers = new TreeView
        {
            Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = Color.White, ForeColor = DesktopTheme.Ink,
            Font = DesktopTheme.Ui, FullRowSelect = true, HideSelection = false, ShowLines = false, ShowRootLines = true,
            AccessibleName = "协议层级", ItemHeight = 24, Indent = 19
        };
        readonly RichTextBox bytes = new RichTextBox
        {
            Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, ReadOnly = true, WordWrap = false,
            DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Both, Font = DesktopTheme.Mono, BackColor = DesktopTheme.Pale,
            ForeColor = DesktopTheme.Ink, AccessibleName = "数据包原始字节"
        };
        readonly Label empty = DesktopTheme.Label("选择上方的数据包以查看协议详情", DesktopTheme.Muted);
        Packet shown;
        bool loading;

        public PacketInspector()
        {
            Dock = DockStyle.Fill;
            var split = new SplitContainer
            {
                Dock = DockStyle.Fill, SplitterWidth = 5, Size = new Size(1000, 250), BackColor = DesktopTheme.Canvas,
                Panel1MinSize = 260, Panel2MinSize = 340, SplitterDistance = 423
            };
            var protocolBody = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(6, 5, 6, 4) };
            empty.TextAlign = ContentAlignment.MiddleCenter;
            protocolBody.Controls.Add(layers);
            protocolBody.Controls.Add(empty);
            split.Panel1.Controls.Add(Pane(frameTitle, protocolBody, Color.White));
            var byteBody = new Panel { Dock = DockStyle.Fill, BackColor = DesktopTheme.Pale, Padding = new Padding(11, 8, 3, 3) };
            byteBody.Controls.Add(bytes);
            split.Panel2.Controls.Add(Pane(byteTitle, byteBody, DesktopTheme.Pale));
            Controls.Add(split);
            layers.AfterSelect += (sender, e) =>
            {
                if (!loading) Highlight(e.Node.Tag is ByteRange ? (ByteRange)e.Node.Tag : default(ByteRange));
            };
            empty.Visible = true;
        }

        static Control Pane(Label title, Control body, Color background)
        {
            var pane = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = background, RowCount = 2, ColumnCount = 1 };
            pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 35));
            pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            title.BackColor = DesktopTheme.Pale;
            title.Padding = new Padding(11, 0, 7, 0);
            pane.Controls.Add(title, 0, 0);
            pane.Controls.Add(body, 0, 1);
            return pane;
        }

        public void ShowPacket(Packet packet)
        {
            if (shown == packet) return;
            shown = packet;
            empty.Visible = packet == null;
            loading = true;
            layers.BeginUpdate();
            try
            {
                layers.Nodes.Clear();
                bytes.Clear();
                frameTitle.Text = packet == null ? "协议层级" : "协议层级  /  帧 #" + packet.Number;
                byteTitle.Text = "原始字节";
                if (packet == null) return;

                byteTitle.Text += packet.Preview.Length == packet.CapturedLength
                    ? "  /  " + packet.CapturedLength + " B"
                    : "  /  预览 " + packet.Preview.Length + " / " + packet.CapturedLength + " B";
                bytes.Text = packet.Hex();
                AddLayer("帧", new ByteRange(0, packet.CapturedLength),
                    packet.Time.ToString("yyyy-MM-dd HH:mm:ss.ffffff"), "原始长度 " + packet.Length + " B",
                    "捕获长度 " + packet.CapturedLength + " B");
                AddLayer("链路层", packet.LinkBytes, packet.LinkInfo);
                AddParsedLayer(packet.Network, packet.IpInfo, packet.NetworkBytes);
                AddParsedLayer(packet.Transport, packet.TransportInfo, packet.TransportBytes);
                if (packet.HttpLine != null) AddLayer("HTTP  /  " + packet.HttpLine, packet.HttpBytes, "首行  " + packet.HttpLine);
                if (packet.Note.Length > 0)
                    layers.Nodes.Add(new TreeNode(packet.Note) { ForeColor = DesktopTheme.Amber });
                layers.TopNode = layers.Nodes[0];
            }
            finally
            {
                layers.EndUpdate();
                loading = false;
            }
        }

        void AddParsedLayer(string name, string fields, ByteRange range)
        {
            if (fields.Length == 0) return;
            string[] lines = fields.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0) return;
            string headline = lines[0].StartsWith(name + " ", StringComparison.Ordinal) ? lines[0] : name + "  /  " + lines[0];
            var root = new TreeNode(headline) { Tag = range };
            foreach (string line in lines)
                foreach (string field in line.Split(new[] { "  ·  " }, StringSplitOptions.RemoveEmptyEntries))
                    root.Nodes.Add(new TreeNode(field) { Tag = range, ForeColor = DesktopTheme.Muted });
            layers.Nodes.Add(root);
        }

        void AddLayer(string name, ByteRange range, params string[] fields)
        {
            var root = new TreeNode(name) { Tag = range };
            foreach (string field in fields)
                root.Nodes.Add(new TreeNode(field) { Tag = range, ForeColor = DesktopTheme.Muted });
            layers.Nodes.Add(root);
        }

        void Highlight(ByteRange range)
        {
            if (shown == null || bytes.TextLength == 0) return;
            const int bytesPerRow = 16;
            const int hexColumn = 7;
            const int asciiColumn = hexColumn + bytesPerRow * 3 + 2;
            bytes.SelectAll();
            bytes.SelectionBackColor = bytes.BackColor;
            int end = Math.Min(range.Offset + range.Length, shown.Preview.Length);
            for (int i = range.Offset; i < end;)
            {
                int column = i % bytesPerRow;
                int count = Math.Min(end - i, bytesPerRow - column);
                int lineStart = bytes.GetFirstCharIndexFromLine(i / bytesPerRow);
                if (lineStart < 0) break;
                bytes.Select(lineStart + hexColumn + column * 3, count * 3 - 1);
                bytes.SelectionBackColor = DesktopTheme.Selected;
                bytes.Select(lineStart + asciiColumn + column, count);
                bytes.SelectionBackColor = DesktopTheme.Selected;
                i += count;
            }
            int first = range.Offset < end ? bytes.GetFirstCharIndexFromLine(range.Offset / bytesPerRow) : 0;
            bytes.Select(Math.Max(0, first), 0);
            bytes.ScrollToCaret();
        }
    }
}
