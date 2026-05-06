"""
idle.pcap — two flows that exercise --flowMaxIdle in -a mode.

Flow A: packets at t=0, +0.05 (RTT match). Goes silent.
Flow B: packets at t=8, +8.05 (one RTT match), keeps the capture clock
        moving so cleanUp gets called past the idle threshold.

Run with --tsvalMaxAge=1 --flowMaxIdle=2 -a: cleanUp at t~=8 evicts
Flow A (idle = 8 - 0.05 = 7.95 > 2) and emits its row using
last_tm = 0.05, NOT capTm = 8.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def _exchange(cip, sip, cport, sport, base_t, cts0, sts0):
    cisn = common.isn()
    sisn = common.isn()

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

    out = []
    # SYN, SYN-ACK, ACK
    out.append((C2S(cisn, 0, "S", b"",
                    common.LIN_OPTS_SYN(cts0)),                     base_t + 0.000))
    out.append((S2C(sisn, cisn + 1, "SA", b"",
                    [("MSS", 1460), ("SAckOK", b""),
                     ("Timestamp", (sts0, cts0)),
                     ("NOP", None), ("WScale", 7)]),                base_t + 0.025))
    out.append((C2S(cisn + 1, sisn + 1, "A", b"",
                    common.LIN_OPTS_DATA(cts0 + 1, sts0)),          base_t + 0.050))
    return out


def build():
    common.seed(20260507)
    pkts = []

    # Flow A: at t=0..0.05
    pkts.extend(_exchange("10.0.0.10", "10.0.1.1", 40000, 53,
                          base_t=1_000_000_000, cts0=100_000, sts0=200_000))
    # Flow B: at t=8..8.05 — keeps capture clock advancing past Flow A's idle threshold
    pkts.extend(_exchange("10.0.0.20", "10.0.1.1", 40001, 53,
                          base_t=1_000_000_008, cts0=300_000, sts0=400_000))

    # Apply timestamps stored in the (pkt, t) tuples
    out = []
    for pkt, t in pkts:
        pkt.time = t
        out.append(pkt)
    return out


if __name__ == "__main__":
    common.write("idle.pcap", build())
