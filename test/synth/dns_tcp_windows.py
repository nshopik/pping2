"""
dns-tcp-windows.pcap — 5 DNS-over-TCP flows (Windows client), no TSopt.
Same packet shape and timing as dns-tcp-linux but TCP options are MSS +
WScale + SACK-Permitted (no Timestamp). Validates the SEQ path's headline
use case: hybrid mode produces samples, ts mode drops them as no_TS.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_500

    for i in range(5):
        cip = f"10.0.2.{10 + i}"
        sip = "10.0.3.1"
        cport = 50000 + i
        sport = 53
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0

        def C2S(seq, ack, flags, payload, opts):
            return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
                   IP(src=cip, dst=sip) / \
                   TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        def S2C(seq, ack, flags, payload, opts):
            return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
                   IP(src=sip, dst=cip) / \
                   TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        seq_steps = []
        seq_steps.append((C2S(cisn, 0, "S", b"", common.WIN_OPTS_SYN), 0))
        seq_steps.append((S2C(sisn, cisn + 1, "SA", b"", common.WIN_OPTS_SYN), 1))
        seq_steps.append((C2S(cisn + 1, sisn + 1, "A", b"", []), 2))
        query = b"\x00\x3a" + b"\x00" * 56
        seq_steps.append((C2S(cisn + 1, sisn + 1, "PA", query, []), 3))
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "A", b"", []), 4))
        resp = b"\x00\x4e" + b"\x00" * 76
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "PA", resp, []), 5))
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "A", b"", []), 6))
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "FA", b"", []), 7))
        seq_steps.append((S2C(sisn + 1 + len(resp), cisn + 2 + len(query),
                              "FA", b"", []), 8))
        seq_steps.append((C2S(cisn + 2 + len(query), sisn + 2 + len(resp),
                              "A", b"", []), 9))

        for pkt, step in seq_steps:
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts


if __name__ == "__main__":
    common.write("dns-tcp-windows.pcap", build())
