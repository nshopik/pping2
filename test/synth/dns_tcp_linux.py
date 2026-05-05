"""
dns-tcp-linux.pcap — 5 DNS-over-TCP flows (Linux client → resolver), TSopt present.
Each flow: SYN, SYN-ACK, ACK, query (PSH-ACK), server ACK, response (PSH-ACK),
client ACK, FIN, FIN-ACK, ACK. ~10 packets * 5 flows = 50 packets.
Each packet is RTT_SEC apart so RTT samples are 0.050000 in golden output.
"""
import time
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260505)
    pkts = []
    base_ts = 1_000_000_000  # epoch seconds for first packet
    base_tsval_c = 100_000   # client TSval starts here, +1 per pkt
    base_tsval_s = 200_000   # server TSval

    for i in range(5):
        cip = f"10.0.0.{10 + i}"
        sip = "10.0.1.1"
        cport = 40000 + i
        sport = 53
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0  # space flows 1s apart

        def C2S(seq, ack, flags, payload, t_off, opts):
            return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
                   IP(src=cip, dst=sip) / \
                   TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        def S2C(seq, ack, flags, payload, t_off, opts):
            return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
                   IP(src=sip, dst=cip) / \
                   TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        # Client TSval increments per packet sent
        cts = base_tsval_c + i * 100
        sts = base_tsval_s + i * 100

        # Packets at +0, +RTT, +2RTT, ... (so query→response RTT = RTT_SEC)
        seq_steps = []
        # 0: SYN C→S
        seq_steps.append((C2S(cisn, 0, "S", b"", 0,
                              common.LIN_OPTS_SYN(cts)), 0))
        # 1: SYN-ACK S→C
        seq_steps.append((S2C(sisn, cisn + 1, "SA", b"", 1,
                              [("MSS", 1460), ("SAckOK", b""),
                               ("Timestamp", (sts, cts)),
                               ("NOP", None), ("WScale", 7)]), 1))
        # 2: ACK C→S
        seq_steps.append((C2S(cisn + 1, sisn + 1, "A", b"", 2,
                              common.LIN_OPTS_DATA(cts + 1, sts)), 2))
        # 3: query PSH-ACK C→S, 60 bytes
        query = b"\x00\x3a" + b"\x00" * 56
        seq_steps.append((C2S(cisn + 1, sisn + 1, "PA", query, 3,
                              common.LIN_OPTS_DATA(cts + 2, sts)), 3))
        # 4: server ACK S→C
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "A", b"", 4,
                              common.LIN_OPTS_DATA(sts + 1, cts + 2)), 4))
        # 5: response PSH-ACK S→C, 80 bytes
        resp = b"\x00\x4e" + b"\x00" * 76
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "PA", resp, 5,
                              common.LIN_OPTS_DATA(sts + 2, cts + 2)), 5))
        # 6: client ACK C→S
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "A", b"", 6,
                              common.LIN_OPTS_DATA(cts + 3, sts + 2)), 6))
        # 7: FIN-ACK C→S
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "FA", b"", 7,
                              common.LIN_OPTS_DATA(cts + 4, sts + 2)), 7))
        # 8: FIN-ACK S→C
        seq_steps.append((S2C(sisn + 1 + len(resp), cisn + 2 + len(query),
                              "FA", b"", 8,
                              common.LIN_OPTS_DATA(sts + 3, cts + 4)), 8))
        # 9: ACK C→S
        seq_steps.append((C2S(cisn + 2 + len(query), sisn + 2 + len(resp),
                              "A", b"", 9,
                              common.LIN_OPTS_DATA(cts + 5, sts + 3)), 9))

        for pkt, step in seq_steps:
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts


if __name__ == "__main__":
    common.write("dns-tcp-linux.pcap", build())
