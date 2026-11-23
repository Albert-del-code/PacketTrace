using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PacketTrace
{
    sealed class Adapter
    {
        public string Name, Label;
        public bool Loopback, Connected;
        public override string ToString() { return Label; }
    }

    sealed class Frame
    {
        public byte[] Bytes;
        public int LinkType, Length;
        public DateTime Time;
    }

    static class Capture
    {
        public const int Snapshot = 262144;
        public static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        const string Library = "wpcap.dll";
        static IntPtr module;
        static readonly object loadLock = new object();

        [StructLayout(LayoutKind.Sequential)]
        struct Device
        {
            public IntPtr Next, Name, Description, Addresses;
            public uint Flags;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_findalldevs(out IntPtr devices, StringBuilder error);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern void pcap_freealldevs(IntPtr devices);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern IntPtr pcap_open_live(string name, int snaplen, int promiscuous, int timeoutMs, StringBuilder error);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_setnonblock(IntPtr handle, int nonblock, StringBuilder error);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_setmintocopy(IntPtr handle, int bytes);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_datalink(IntPtr handle);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr pcap_geterr(IntPtr handle);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
        static extern void pcap_close(IntPtr handle);

        static void Load()
        {
            lock (loadLock)
            {
                if (module != IntPtr.Zero) return;
                string path = Path.Combine(Environment.SystemDirectory, "Npcap", Library);
                if (!File.Exists(path)) throw new InvalidOperationException("找不到 Npcap。安装后点「刷新网卡」，或打开已有的 .pcap 文件。");
                // 从 Npcap 安装目录和系统目录查找依赖。
                module = LoadLibraryEx(path, IntPtr.Zero, 0x00000900);
                if (module == IntPtr.Zero)
                    throw new InvalidOperationException("无法加载 Npcap（Windows 错误 " + Marshal.GetLastWin32Error() + "）。请检查安装。");
            }
        }

        public static List<Adapter> Adapters()
        {
            Load();
            var result = new List<Adapter>();
            var error = new StringBuilder(256);
            IntPtr first;
            if (pcap_findalldevs(out first, error) != 0) throw new InvalidOperationException(error.ToString());
            try
            {
                for (IntPtr item = first; item != IntPtr.Zero;)
                {
                    var device = (Device)Marshal.PtrToStructure(item, typeof(Device));
                    string name = Marshal.PtrToStringAnsi(device.Name);
                    string label = Marshal.PtrToStringAnsi(device.Description);
                    bool loopback = (device.Flags & 1) != 0 || name.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase);
                    result.Add(new Adapter
                    {
                        Name = name, Label = loopback ? "本机回环（127.0.0.1 / ::1）" : label ?? name,
                        Loopback = loopback, Connected = (device.Flags & 0x30) == 0x10
                    });
                    item = device.Next;
                }
            }
            finally { if (first != IntPtr.Zero) pcap_freealldevs(first); }
            return result;
        }

        public static void ReadLive(Adapter adapter, CancellationToken token, Action<int> ready, Action<Frame> receive)
        {
            Load();
            var error = new StringBuilder(256);
            IntPtr handle = pcap_open_live(adapter.Name, Snapshot, 0, 50, error);
            if (handle == IntPtr.Zero) throw new InvalidOperationException("打开网卡失败：" + error);
            try
            {
                int link = pcap_datalink(handle);
                if (!PacketParser.Supports(link)) throw new InvalidOperationException("此网卡的链路类型暂不支持：" + link);
                // 少量回环报文也及时交付，避免等待缓冲区积累。
                if (pcap_setmintocopy(handle, 1) != 0)
                    throw new InvalidOperationException("无法设置抓包缓冲区：" + Marshal.PtrToStringAnsi(pcap_geterr(handle)));
                if (pcap_setnonblock(handle, 1, error) != 0) throw new InvalidOperationException("无法启用可停止的抓包模式：" + error);
                ready(link);
                while (!token.IsCancellationRequested)
                {
                    IntPtr header, data;
                    int state = pcap_next_ex(handle, out header, out data);
                    if (state == 0) { Thread.Sleep(10); continue; }
                    if (state < 0)
                        throw new InvalidOperationException("抓包中断：" + Marshal.PtrToStringAnsi(pcap_geterr(handle)));
                    // Windows 的 timeval 字段在 64 位进程中仍为两个 32 位整数。
                    uint seconds = unchecked((uint)Marshal.ReadInt32(header, 0));
                    int microseconds = Marshal.ReadInt32(header, 4);
                    int captured = Marshal.ReadInt32(header, 8);
                    int original = Marshal.ReadInt32(header, 12);
                    if (captured < 0 || captured > Snapshot || original < captured) continue;
                    var bytes = new byte[captured];
                    Marshal.Copy(data, bytes, 0, captured);
                    receive(new Frame
                    {
                        Bytes = bytes, LinkType = link, Length = original,
                        Time = Epoch.AddSeconds(seconds).AddTicks(microseconds * 10L).ToLocalTime()
                    });
                }
            }
            finally { pcap_close(handle); }
        }

        public static void ReadFile(string path, CancellationToken token, Action<Frame> receive)
        {
            using (var reader = new BinaryReader(File.OpenRead(path)))
            {
                byte[] header = reader.ReadBytes(24);
                if (header.Length != 24) throw new InvalidDataException("文件头不完整。");
                uint magic = BitConverter.ToUInt32(header, 0);
                bool swap = magic == 0xD4C3B2A1 || magic == 0x4D3CB2A1;
                bool nanos = magic == 0xA1B23C4D || magic == 0x4D3CB2A1;
                if (magic != 0xA1B2C3D4 && !swap && !nanos)
                    throw new InvalidDataException("请选择传统 .pcap 文件（Wireshark 保存时可选 pcap 格式）。");
                int link = (int)(Read32(header, 20, swap) & 65535);
                if (!PacketParser.Supports(link)) throw new InvalidDataException("暂不支持此链路类型：" + link);
                while (!token.IsCancellationRequested && reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    byte[] record = reader.ReadBytes(16);
                    if (record.Length < 16) throw new InvalidDataException("数据包记录头不完整。");
                    uint seconds = Read32(record, 0, swap), fraction = Read32(record, 4, swap);
                    uint captured = Read32(record, 8, swap), original = Read32(record, 12, swap);
                    if (captured > Snapshot || original > int.MaxValue || captured > original ||
                        fraction >= (nanos ? 1000000000u : 1000000u))
                        throw new InvalidDataException("数据包长度或时间戳无效。");
                    byte[] bytes = reader.ReadBytes((int)captured);
                    if (bytes.Length != (int)captured) throw new InvalidDataException("数据包内容不完整。");
                    receive(new Frame
                    {
                        Bytes = bytes, LinkType = link, Length = (int)original,
                        Time = Epoch.AddSeconds(seconds).AddTicks(nanos ? fraction / 100L : fraction * 10L).ToLocalTime()
                    });
                }
            }
        }

        public static void WriteFile(string path, IList<Frame> frames)
        {
            if (frames.Count == 0) throw new ArgumentException("没有可保存的数据包。");
            string destination = Path.GetFullPath(path);
            string temporary = Path.Combine(Path.GetDirectoryName(destination), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var writer = new BinaryWriter(new FileStream(temporary, FileMode.CreateNew, FileAccess.Write)))
                {
                    writer.Write(0xA1B2C3D4u);
                    writer.Write((ushort)2);
                    writer.Write((ushort)4);
                    writer.Write(0u);
                    writer.Write(0u);
                    writer.Write((uint)Snapshot);
                    writer.Write((uint)frames[0].LinkType);
                    foreach (Frame frame in frames)
                    {
                        long elapsed = (frame.Time.ToUniversalTime() - Epoch).Ticks;
                        writer.Write((uint)(elapsed / TimeSpan.TicksPerSecond));
                        writer.Write((uint)(elapsed % TimeSpan.TicksPerSecond / 10));
                        writer.Write((uint)frame.Bytes.Length);
                        writer.Write((uint)frame.Length);
                        writer.Write(frame.Bytes);
                    }
                }
                if (File.Exists(destination)) File.Replace(temporary, destination, null);
                else File.Move(temporary, destination);
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    try { File.Delete(temporary); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }

        static uint Read32(byte[] bytes, int offset, bool swap)
        {
            return swap ? ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) |
                ((uint)bytes[offset + 2] << 8) | bytes[offset + 3] : BitConverter.ToUInt32(bytes, offset);
        }
    }
}
