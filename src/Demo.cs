using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PacketTrace
{
    static class Demo
    {
        public static int Run()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            try
            {
                Task server = Task.Run(() => { Serve(listener); Serve(listener); });
                if (Request(port, "/") != "HTTP/1.1 200 OK" || Request(port, "/missing") != "HTTP/1.1 404 Not Found")
                    throw new IOException("本地网站的响应与预期不符。");
                if (!server.Wait(6000)) throw new IOException("本地网站没有完成演示请求。");
            }
            finally { listener.Stop(); }

            try { Request(port, "/"); }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionRefused) return port;
                throw;
            }
            throw new IOException("本地端口仍接受连接，请重试。");
        }

        static void Serve(TcpListener listener)
        {
            using (var connection = listener.AcceptTcpClient())
            {
                connection.ReceiveTimeout = 3000;
                connection.SendTimeout = 3000;
                using (NetworkStream stream = connection.GetStream())
                using (var reader = new StreamReader(stream, Encoding.ASCII))
                {
                    string request = reader.ReadLine();
                    for (string line = reader.ReadLine(); !string.IsNullOrEmpty(line); line = reader.ReadLine()) { }
                    bool ok = request == "GET / HTTP/1.1";
                    string body = ok ? "Hello from PacketTrace\n" : "Page not found\n";
                    string response = "HTTP/1.1 " + (ok ? "200 OK" : "404 Not Found") +
                        "\r\nContent-Type: text/plain\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n" + body;
                    byte[] bytes = Encoding.ASCII.GetBytes(response);
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
        }

        static string Request(int port, string path)
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                client.ReceiveTimeout = 3000;
                client.SendTimeout = 3000;
                IAsyncResult connect = client.BeginConnect(IPAddress.Loopback, port, null, null);
                using (WaitHandle done = connect.AsyncWaitHandle)
                {
                    if (!done.WaitOne(4000)) throw new IOException("连接本地网站超时。");
                    client.EndConnect(connect);
                }
                using (NetworkStream stream = client.GetStream())
                using (var reader = new StreamReader(stream, Encoding.ASCII))
                {
                    byte[] request = Encoding.ASCII.GetBytes("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n");
                    stream.Write(request, 0, request.Length);
                    string status = reader.ReadLine();
                    reader.ReadToEnd();
                    return status;
                }
            }
        }

        public static string Record(string path)
        {
            Adapter adapter = Capture.Adapters().Find(a => a.Loopback);
            if (adapter == null) throw new InvalidOperationException("没有找到 Npcap 回环网卡。");
            var frames = new List<Frame>();
            int port;
            using (var ready = new ManualResetEventSlim())
            using (var stop = new CancellationTokenSource())
            {
                Task task = Task.Run(() => Capture.ReadLive(adapter, stop.Token, _ => ready.Set(),
                    frame => { if (frames.Count < 20000) frames.Add(frame); }));
                try
                {
                    if (WaitHandle.WaitAny(new[] { ready.WaitHandle, ((IAsyncResult)task).AsyncWaitHandle }, 7000) != 0)
                    {
                        if (task.IsCompleted) task.GetAwaiter().GetResult();
                        throw new IOException("回环抓包没有启动。");
                    }
                    try { using (var ping = new Ping()) ping.Send(IPAddress.Loopback, 1000); }
                    catch (PingException) { /* ping 不可用时继续验证 TCP。 */ }
                    port = Run();
                    Thread.Sleep(700);
                }
                finally
                {
                    stop.Cancel();
                    task.GetAwaiter().GetResult();
                }
            }
            var flows = new TcpFlows();
            var chosen = new List<Frame>();
            var found = new HashSet<TcpFlow>();
            int icmp = 0;
            foreach (Frame frame in frames)
            {
                Packet packet = PacketParser.Parse(frame.Bytes, frame.LinkType, frame.Time, frame.Length);
                if (packet.Transport == "ICMP" && packet.Source == "127.0.0.1" && packet.Destination == "127.0.0.1")
                {
                    icmp++;
                    chosen.Add(frame);
                }
                if (packet.SourcePort != port && packet.DestinationPort != port) continue;
                packet.Number = chosen.Count + 1;
                flows.Add(packet);
                if (packet.Flow != null) found.Add(packet.Flow);
                chosen.Add(frame);
            }
            if (chosen.Count == 0) throw new IOException("回环网卡上没有抓到演示数据。");
            Capture.WriteFile(path, chosen);
            bool ok = false, missing = false, refused = false;
            foreach (TcpFlow flow in found)
            {
                ok |= flow.HttpStatus == 200;
                missing |= flow.HttpStatus == 404;
                refused |= flow.Refused;
            }
            string summary = "Frames=" + chosen.Count + "; ICMP=" + icmp + "; HTTP 200=" + ok +
                "; HTTP 404=" + missing + "; Refused=" + refused + "; Port=" + port;
            if (!(ok && missing && refused)) throw new IOException(summary);
            return summary;
        }
    }
}
