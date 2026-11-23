using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace PacketTrace
{
    static class DesktopTheme
    {
        public static readonly Color Ink = Color.FromArgb(27, 43, 64);
        public static readonly Color Muted = Color.FromArgb(82, 101, 124);
        public static readonly Color Navy = Color.FromArgb(19, 32, 52);
        public static readonly Color Blue = Color.FromArgb(36, 87, 192);
        public static readonly Color Canvas = Color.FromArgb(234, 239, 246);
        public static readonly Color Pale = Color.FromArgb(247, 249, 252);
        public static readonly Color Line = Color.FromArgb(217, 226, 237);
        public static readonly Color Selected = Color.FromArgb(219, 233, 255);
        public static readonly Color Teal = Color.FromArgb(15, 109, 91);
        public static readonly Color Amber = Color.FromArgb(147, 83, 17);
        public static readonly Color Red = Color.FromArgb(168, 45, 56);
        public static readonly Font Ui = new Font("Microsoft YaHei UI", 9F);
        public static readonly Font UiBold = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold);
        public static readonly Font Mono = new Font("Consolas", 9F);
        public static readonly Font MonoBold = new Font("Consolas", 9F, FontStyle.Bold);

        public static Label Label(string text, Color color, Font font = null)
        {
            return new Label { Text = text, ForeColor = color, Font = font ?? Ui, AutoEllipsis = true,
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Margin = Padding.Empty };
        }

        public static GraphicsPath Rounded(Rectangle bounds, int radius)
        {
            var path = new GraphicsPath();
            int diameter = radius * 2;
            path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180, 90);
            path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270, 90);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }

        public static void Glyph(Graphics graphics, string icon, Rectangle area, Color color)
        {
            GraphicsState state = graphics.Save();
            graphics.TranslateTransform(area.X, area.Y);
            graphics.ScaleTransform(area.Width / 16f, area.Height / 16f);
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var pen = new Pen(color, 1.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
            using (var brush = new SolidBrush(color))
            {
                switch (icon)
                {
                    case "trace":
                        graphics.DrawLines(pen, new[] { new Point(1, 10), new Point(4, 10), new Point(6, 4),
                            new Point(9, 13), new Point(11, 7), new Point(15, 7) });
                        break;
                    case "open":
                        graphics.DrawLines(pen, new[] { new Point(1, 12), new Point(1, 4), new Point(6, 4),
                            new Point(8, 6), new Point(14, 6), new Point(14, 8) });
                        graphics.DrawPolygon(pen, new[] { new Point(1, 13), new Point(4, 8), new Point(15, 8), new Point(12, 13) });
                        break;
                    case "start":
                        graphics.FillPolygon(brush, new[] { new Point(4, 2), new Point(14, 8), new Point(4, 14) });
                        break;
                    case "stop":
                        graphics.FillRectangle(brush, 3, 3, 10, 10);
                        break;
                    case "refresh":
                        graphics.DrawArc(pen, 2, 2, 12, 12, 35, 295);
                        graphics.DrawLines(pen, new[] { new Point(10, 6), new Point(14, 6), new Point(14, 2) });
                        break;
                    case "filter":
                        graphics.DrawPolygon(pen, new[] { new Point(1, 2), new Point(15, 2), new Point(10, 8),
                            new Point(10, 12), new Point(6, 14), new Point(6, 8) });
                        break;
                    case "search":
                        graphics.DrawEllipse(pen, 2, 2, 9, 9);
                        graphics.DrawLine(pen, 10, 10, 14, 14);
                        break;
                    case "list":
                        for (int y = 3; y <= 13; y += 5)
                        {
                            graphics.DrawLine(pen, 2, y, 3, y);
                            graphics.DrawLine(pen, 6, y, 14, y);
                        }
                        break;
                    case "demo":
                        graphics.DrawLines(pen, new[] { new Point(5, 2), new Point(11, 2), new Point(10, 2),
                            new Point(10, 7), new Point(14, 13), new Point(13, 14), new Point(3, 14),
                            new Point(2, 13), new Point(6, 7), new Point(6, 2) });
                        graphics.DrawLine(pen, 4, 10, 12, 10);
                        break;
                }
            }
            graphics.Restore(state);
        }
    }

    sealed class CaptureBadge : Label
    {
        protected override void OnPaint(PaintEventArgs e)
        {
            if (Width < 16 || Height < 16) return;
            e.Graphics.Clear(Parent == null ? DesktopTheme.Navy : Parent.BackColor);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = DesktopTheme.Rounded(new Rectangle(0, 0, Width - 1, Height - 1), 7))
            using (var fill = new SolidBrush(BackColor))
                e.Graphics.FillPath(fill, path);
            e.Graphics.FillEllipse(Brushes.White, 12, (Height - 6) / 2, 6, 6);
            TextRenderer.DrawText(e.Graphics, Text, DesktopTheme.UiBold, new Rectangle(24, 0, Width - 28, Height),
                Color.White, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }
    }

    sealed class ActionButton : Button
    {
        readonly string glyph;
        readonly bool primary;
        bool hover, pressed;

        public ActionButton(string text, int width, string glyph = null, bool primary = false)
        {
            Text = text;
            this.glyph = glyph;
            this.primary = primary;
            Size = new Size(width, 32);
            Margin = new Padding(0, 0, 7, 0);
            Font = DesktopTheme.Ui;
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            UseVisualStyleBackColor = false;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
        }

        protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); hover = true; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hover = false; pressed = false; Invalidate(); }
        protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); pressed = e.Button == MouseButtons.Left; Invalidate(); }
        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); pressed = false; Invalidate(); }
        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }
        protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
        protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Parent == null ? Color.White : Parent.BackColor);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color fill = !Enabled ? DesktopTheme.Pale : primary
                ? (pressed ? Color.FromArgb(26, 61, 143) : hover ? Color.FromArgb(43, 101, 214) : DesktopTheme.Blue)
                : pressed ? DesktopTheme.Selected : hover ? Color.FromArgb(237, 244, 255) : Color.White;
            Color text = !Enabled ? Color.FromArgb(112, 128, 149) : primary ? Color.White : DesktopTheme.Ink;
            Color line = Enabled && primary ? fill : DesktopTheme.Line;
            using (var shape = DesktopTheme.Rounded(new Rectangle(0, 0, Width - 1, Height - 1), 5))
            using (var brush = new SolidBrush(fill))
            using (var pen = new Pen(line))
            {
                g.FillPath(brush, shape);
                g.DrawPath(pen, shape);
            }
            int icon = Math.Max(14, Height / 2);
            const TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine |
                TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix;
            int textWidth = TextRenderer.MeasureText(g, Text, Font, Size.Empty, flags).Width;
            int left = glyph == null ? 0 : Math.Max(5, (Width - (icon + (Text.Length == 0 ? 0 : 6 + textWidth))) / 2);
            if (glyph != null) DesktopTheme.Glyph(g, glyph, new Rectangle(left, (Height - icon) / 2, icon, icon), text);
            int textLeft = glyph == null ? 0 : left + icon + 6;
            if (Text.Length != 0)
                TextRenderer.DrawText(g, Text, Font, new Rectangle(textLeft, 0, Width - textLeft, Height), text,
                    flags | (glyph == null ? TextFormatFlags.HorizontalCenter : TextFormatFlags.Left));
            if (Focused && ShowFocusCues)
                ControlPaint.DrawFocusRectangle(g, Rectangle.Inflate(ClientRectangle, -4, -4), text, fill);
        }
    }
}
