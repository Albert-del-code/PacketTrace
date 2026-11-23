using System;
using System.Collections.Generic;

namespace PacketTrace
{
    sealed class TcpFlow
    {
        public readonly string Client, Server;
        public readonly DateTime Started;
        public readonly int FirstPacket;
        public readonly bool SawSyn, KnowsInitiator;
        public readonly uint SynSeq;
        public int LastPacket;
        public int HttpStatus { get; private set; }
        public bool Refused { get; private set; }
        bool sawSynAck, established, reset;
        uint synAckSeq;

        public TcpFlow(Packet first)
        {
            bool startsWithSynAck = first.Syn && first.AckFlag;
            Client = first.Endpoint(!startsWithSynAck);
            Server = first.Endpoint(startsWithSynAck);
            SawSyn = first.Syn && !first.AckFlag;
            KnowsInitiator = first.Syn;
            SynSeq = first.Seq;
            Started = first.Time;
            FirstPacket = first.Number;
        }

        public void Add(Packet packet)
        {
            packet.Flow = this;
            LastPacket = packet.Number;
            bool forward = packet.Endpoint(true) == Client;
            if (SawSyn && !forward && packet.AckFlag && packet.Ack == unchecked(SynSeq + 1))
            {
                if (packet.Syn && !packet.Reset)
                {
                    sawSynAck = true;
                    synAckSeq = packet.Seq;
                    if (Refused) reset = false;
                    Refused = false;
                }
                if (packet.Reset && !sawSynAck) Refused = true;
            }
            if (sawSynAck && forward && !packet.Syn && !packet.Reset && packet.AckFlag && packet.Ack == unchecked(synAckSeq + 1))
                established = true;
            if (packet.HttpStatus >= 200) HttpStatus = packet.HttpStatus;
            if (packet.Reset) reset = true;
        }

        public string OutcomeFor(Packet selected)
        {
            int status = selected.HttpStatus != 0 ? selected.HttpStatus : HttpStatus;
            if (status == 200) return "网页正常返回 · HTTP 200";
            if (status == 404) return "页面不存在 · HTTP 404";
            if (status > 0) return "收到 HTTP 响应 · " + status;
            if (Refused) return "连接被拒绝 · 对端在握手时回复 RST";
            if (reset) return "连接被重置 · 观察到 RST";
            if (established) return "TCP 握手完成 · 尚未看到 HTTP 响应";
            if (sawSynAck) return "观察到 SYN 和 SYN/ACK · 尚未看到第三次握手";
            if (SawSyn) return "观察到 SYN · 尚未看到对端响应";
            return "抓包未包含完整握手 · 无法确认连接建立过程";
        }
    }

    sealed class TcpFlows
    {
        readonly Dictionary<string, TcpFlow> current = new Dictionary<string, TcpFlow>();

        public void Add(Packet packet)
        {
            if (packet.Transport != "TCP") return;
            string source = packet.Endpoint(true), destination = packet.Endpoint(false);
            string key = string.CompareOrdinal(source, destination) <= 0 ? source + "|" + destination : destination + "|" + source;
            TcpFlow flow;
            if (!current.TryGetValue(key, out flow) ||
                (packet.Syn && !packet.AckFlag &&
                    (!flow.SawSyn || flow.SynSeq != packet.Seq || flow.Client != source ||
                    packet.Time - flow.Started > TimeSpan.FromMinutes(2))))
                current[key] = flow = new TcpFlow(packet);
            flow.Add(packet);
        }

        public void Prune(int beforePacket)
        {
            var old = new List<string>();
            foreach (var item in current)
                if (item.Value.LastPacket < beforePacket) old.Add(item.Key);
            foreach (string key in old) current.Remove(key);
        }
    }
}
