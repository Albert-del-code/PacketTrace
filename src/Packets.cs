using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PacketTrace
{
    struct ByteRange
    {
        public readonly int Offset, Length;
        public ByteRange(int offset, int length) { Offset = offset; Length = length; }
    }

    sealed class Packet
    {
        public int Number, Length, CapturedLength, LinkType, IpVersion;
        public int SourcePort = -1, DestinationPort = -1, PayloadLength;
        public DateTime Time;
        public string Source = "", Destination = "", Network = "", Transport = "";
        public string LinkInfo = "", IpInfo = "", TransportInfo = "", Note = "";
        public byte[] Preview;
        public uint Seq, Ack;
        public int Flags;
        public string HttpLine;
        public int HttpStatus;
        public TcpFlow Flow;
        public Frame RawFrame;
        public ByteRange LinkBytes, NetworkBytes, TransportBytes, HttpBytes;

        public bool Syn { get { return (Flags & 2) != 0; } }
        public bool AckFlag { get { return (Flags & 16) != 0; } }
        public bool Fin { get { return (Flags & 1) != 0; } }
        public bool Reset { get { return (Flags & 4) != 0; } }
        public string Protocol { get { return HttpLine != null ? "HTTP" : Transport != "" ? Transport : Network != "" ? Network : "链路层"; } }
        public string Summary
        {
            get
            {
                if (HttpLine != null) return HttpLine;
                if (Transport == "TCP") return FlagNames() + (PayloadLength > 0 ? "  ·  " + PayloadLength + " B 数据" : "");
                if (Transport == "UDP") return PayloadLength + " B 数据";
                if (Transport.StartsWith("ICMP", StringComparison.Ordinal)) return TransportInfo.Split('\n')[0];
                if (Network == "ARP" && IpInfo != "") return IpInfo.Split('\n')[0].TrimEnd('\r');
                return Note;
            }
        }

        public string Endpoint(bool source)
        {
            string address = source ? Source : Destination;
            int port = source ? SourcePort : DestinationPort;
            if (address == "") return "—";
            if (port < 0) return address;
            return (IpVersion == 6 ? "[" + address + "]" : address) + ":" + port;
        }

        public string FlagNames()
        {
            string[] labels = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" };
            var active = new List<string>();
            for (int i = 0; i < labels.Length; ++i)
                if ((Flags & (1 << i)) != 0) active.Add(labels[i]);
            return active.Count > 0 ? string.Join(", ", active) : "无标志";
        }

        public bool Matches(string protocol, string search)
        {
            if (protocol != "全部协议" && protocol != Network && protocol != Transport &&
                protocol != Protocol && !(protocol == "ICMP" && Transport == "ICMPv6"))
                return false;
            if (search == "") return true;
            int port;
            if (int.TryParse(search, NumberStyles.None, CultureInfo.InvariantCulture, out port))
                return SourcePort == port || DestinationPort == port;
            return Endpoint(true).IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                Endpoint(false).IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public string Hex()
        {
            var b = new StringBuilder();
            for (int i = 0; i < Preview.Length; i += 16)
            {
                b.AppendFormat("{0:X4}   ", i);
                for (int j = i; j < i + 16; ++j)
                    b.Append(j < Preview.Length ? Preview[j].ToString("X2") + " " : "   ");
                b.Append("  ");
                for (int j = i; j < Math.Min(i + 16, Preview.Length); ++j)
                    b.Append(Preview[j] >= 32 && Preview[j] <= 126 ? (char)Preview[j] : '.');
                b.AppendLine();
            }
            return b.ToString();
        }
    }

    static class PacketParser
    {
        static readonly Regex Response = new Regex(@"^HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7E]*)?$", RegexOptions.CultureInvariant);
        static readonly Regex Request = new Regex(@"^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [!-~]+ HTTP/1\.[01]$", RegexOptions.CultureInvariant);

        public static bool Supports(int linkType)
        {
            return linkType == 0 || linkType == 1 || linkType == 12 || linkType == 101 ||
                linkType == 108 || linkType == 113 || linkType == 228 || linkType == 229 || linkType == 276;
        }

        public static Packet Parse(byte[] bytes, int link, DateTime time, int originalLength)
        {
            var p = new Packet { Time = time, LinkType = link, Length = originalLength, CapturedLength = bytes.Length };
            p.Preview = new byte[Math.Min(bytes.Length, 512)];
            Buffer.BlockCopy(bytes, 0, p.Preview, 0, p.Preview.Length);
            int offset = 0, type = 0;
            p.LinkInfo = "链路类型 " + link;
            if (link == 1)
            {
                if (bytes.Length < 14) return Short(p, "以太网帧头不完整");
                type = U16(bytes, 12);
                offset = 14;
                p.LinkInfo = "以太网  " + BitConverter.ToString(bytes, 6, 6) + " → " + BitConverter.ToString(bytes, 0, 6);
                while (type == 0x8100 || type == 0x88A8)
                {
                    if (bytes.Length < offset + 4) return Short(p, "VLAN 标签不完整");
                    p.LinkInfo += "  VLAN " + (U16(bytes, offset) & 4095);
                    type = U16(bytes, offset + 2);
                    offset += 4;
                }
                p.LinkInfo += "  EtherType 0x" + type.ToString("X4");
            }
            else if (link == 0 || link == 108)
            {
                if (bytes.Length < 4) return Short(p, "回环头不完整");
                offset = 4;
                uint family = link == 0 ? BitConverter.ToUInt32(bytes, 0) : U32(bytes, 0);
                // DLT_NULL 的地址族字段采用抓包主机的字节序。
                if (link == 0 && family > 255) family = U32(bytes, 0);
                type = family == 2 ? 0x0800 :
                    family == 10 || family == 23 || family == 24 || family == 28 || family == 30 ? 0x86DD : 0;
                p.LinkInfo = "回环  地址族 " + family;
            }
            else if (link == 113 || link == 276)
            {
                offset = link == 113 ? 16 : 20;
                if (bytes.Length < offset) return Short(p, "链路层头不完整");
                type = U16(bytes, link == 113 ? 14 : 0);
                p.LinkInfo = link == 113 ? "Linux SLL" : "Linux SLL2";
            }
            else if (link == 12 || link == 101 || link == 228 || link == 229)
            {
                if (bytes.Length == 0) return Short(p, "空帧");
                type = link == 228 || (bytes[0] >> 4) == 4 ? 0x0800 :
                    link == 229 || (bytes[0] >> 4) == 6 ? 0x86DD : 0;
                p.LinkInfo = "原始 IP";
            }
            else return Short(p, "暂不解析此链路类型");
            p.LinkBytes = new ByteRange(0, offset);

            if (type == 0x0806)
            {
                p.Network = "ARP";
                if (bytes.Length >= offset + 28 && U16(bytes, offset + 2) == 0x0800 &&
                    bytes[offset + 4] == 6 && bytes[offset + 5] == 4)
                {
                    p.Source = Address(bytes, offset + 14, 4);
                    p.Destination = Address(bytes, offset + 24, 4);
                    p.NetworkBytes = new ByteRange(offset, 28);
                    p.IpInfo = "ARP  " + p.Source + " → " + p.Destination +
                        "\r\n操作 " + U16(bytes, offset + 6);
                }
                return p;
            }

            int next, end;
            bool moreFragments = false;
            if (type == 0x0800)
            {
                p.Network = "IPv4";
                p.IpVersion = 4;
                if (bytes.Length < offset + 20 || bytes[offset] >> 4 != 4) return Short(p, "IPv4 头不完整或版本不符");
                int header = (bytes[offset] & 15) * 4;
                int total = U16(bytes, offset + 2);
                if (header < 20 || total < header || bytes.Length < offset + header) return Short(p, "IPv4 头长度无效");
                p.NetworkBytes = new ByteRange(offset, header);
                p.Source = Address(bytes, offset + 12, 4);
                p.Destination = Address(bytes, offset + 16, 4);
                next = bytes[offset + 9];
                p.IpInfo = "IPv4  " + p.Source + " → " + p.Destination +
                    "\r\n头部 " + header + " B  ·  总长度 " + total + " B  ·  TTL " + bytes[offset + 8] + "  ·  协议号 " + next;
                int frag = U16(bytes, offset + 6);
                if ((frag & 8191) != 0) return Short(p, "IPv4 后续分片");
                moreFragments = (frag & 8192) != 0;
                end = Math.Min(bytes.Length, offset + total);
                offset += header;
            }
            else if (type == 0x86DD)
            {
                p.Network = "IPv6";
                p.IpVersion = 6;
                if (bytes.Length < offset + 40 || bytes[offset] >> 4 != 6) return Short(p, "IPv6 头不完整或版本不符");
                p.Source = Address(bytes, offset + 8, 16);
                p.Destination = Address(bytes, offset + 24, 16);
                int length = U16(bytes, offset + 4);
                next = bytes[offset + 6];
                p.IpInfo = "IPv6  " + p.Source + " → " + p.Destination + "\r\n载荷 " + length +
                    " B  ·  Hop Limit " + bytes[offset + 7] + "  ·  Next Header " + next;
                int networkStart = offset;
                p.NetworkBytes = new ByteRange(networkStart, 40);
                end = Math.Min(bytes.Length, offset + 40 + length);
                offset += 40;
                while (next == 0 || next == 43 || next == 44 || next == 51 || next == 60)
                {
                    if (end - offset < 2) return Short(p, "IPv6 扩展头不完整");
                    int header = next == 44 ? 8 : next == 51 ? (bytes[offset + 1] + 2) * 4 : (bytes[offset + 1] + 1) * 8;
                    if (end - offset < header) return Short(p, "IPv6 扩展头不完整");
                    p.NetworkBytes = new ByteRange(networkStart, offset + header - networkStart);
                    if (next == 44)
                    {
                        int frag = U16(bytes, offset + 2);
                        if ((frag & 0xFFF8) != 0) return Short(p, "IPv6 后续分片");
                        moreFragments = (frag & 1) != 0;
                    }
                    next = bytes[offset];
                    offset += header;
                }
            }
            else return p;

            if (next == 6)
            {
                if (end - offset < 20) return Short(p, "TCP 头不完整");
                int header = (bytes[offset + 12] >> 4) * 4;
                if (header < 20 || end - offset < header) return Short(p, "TCP 头长度无效");
                p.Transport = "TCP";
                p.TransportBytes = new ByteRange(offset, header);
                p.SourcePort = U16(bytes, offset);
                p.DestinationPort = U16(bytes, offset + 2);
                p.Seq = U32(bytes, offset + 4);
                p.Ack = U32(bytes, offset + 8);
                p.Flags = bytes[offset + 13];
                p.PayloadLength = end - offset - header;
                p.TransportInfo = "TCP  " + p.SourcePort + " → " + p.DestinationPort +
                    "\n标志 " + p.FlagNames() + "  ·  Seq " + p.Seq + "  ·  Ack " + p.Ack +
                    "\n头部 " + header + " B  ·  窗口 " + U16(bytes, offset + 14) + "  ·  捕获的载荷 " + p.PayloadLength + " B";
                if (!moreFragments && p.PayloadLength > 0) DecodeHttp(p, bytes, offset + header, end);
            }
            else if (next == 17)
            {
                if (end - offset < 8) return Short(p, "UDP 头不完整");
                int length = U16(bytes, offset + 4);
                if (length < 8) return Short(p, "UDP 长度无效");
                p.Transport = "UDP";
                p.TransportBytes = new ByteRange(offset, 8);
                p.SourcePort = U16(bytes, offset);
                p.DestinationPort = U16(bytes, offset + 2);
                p.PayloadLength = Math.Min(length, end - offset) - 8;
                p.TransportInfo = "UDP  " + p.SourcePort + " → " + p.DestinationPort + "\n报文长度 " + length + " B";
            }
            else if ((p.IpVersion == 4 && next == 1) || (p.IpVersion == 6 && next == 58))
            {
                if (end - offset < 4) return Short(p, "ICMP 头不完整");
                bool v6 = p.IpVersion == 6;
                int code = bytes[offset + 1], kind = bytes[offset];
                p.Transport = v6 ? "ICMPv6" : "ICMP";
                string name = kind == (v6 ? 128 : 8) ? "Echo 请求" : kind == (v6 ? 129 : 0) ? "Echo 应答" : "";
                p.TransportBytes = new ByteRange(offset, name != "" && end - offset >= 8 ? 8 : 4);
                p.TransportInfo = (name != "" ? name + "  ·  " : "") + "类型 " + kind + "  ·  代码 " + code;
                if (name != "" && end - offset >= 8)
                    p.TransportInfo += "\n标识 " + U16(bytes, offset + 4) + "  ·  序号 " + U16(bytes, offset + 6);
            }
            if (moreFragments) p.Note = "IP 首分片，仅展示本帧已有字段。";
            return p;
        }

        static void DecodeHttp(Packet p, byte[] bytes, int start, int end)
        {
            int limit = Math.Min(end - 1, start + 2048);
            for (int i = start; i < limit; i++)
            {
                if (bytes[i] == 13 && bytes[i + 1] == 10)
                {
                    string line = Encoding.ASCII.GetString(bytes, start, i - start);
                    Match response = Response.Match(line);
                    if (response.Success)
                    {
                        p.HttpLine = line;
                        p.HttpStatus = int.Parse(response.Groups[1].Value, CultureInfo.InvariantCulture);
                    }
                    else if (Request.IsMatch(line)) p.HttpLine = line;
                    if (p.HttpLine != null) p.HttpBytes = new ByteRange(start, i - start + 2);
                    return;
                }
                if (bytes[i] < 32 || bytes[i] > 126) return;
            }
        }

        static Packet Short(Packet p, string note) { p.Note = note; return p; }
        static int U16(byte[] bytes, int offset) { return (bytes[offset] << 8) | bytes[offset + 1]; }
        static uint U32(byte[] bytes, int offset) { return ((uint)U16(bytes, offset) << 16) | (uint)U16(bytes, offset + 2); }
        static string Address(byte[] bytes, int offset, int count)
        {
            var value = new byte[count];
            Buffer.BlockCopy(bytes, offset, value, 0, count);
            return new IPAddress(value).ToString();
        }
    }
}
