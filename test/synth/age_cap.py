"""
age_cap.pcap — single long-lived TCP flow whose capture-time spans ~12s,
designed to exercise the -a / --flowMaxAge cap with a small test value
(typically --flowMaxAge=5).

Exchange pattern repeats every 1s of capture-time:
    C -> S  data (PSH-ACK, payload)        at t=1, 2, 3, ...
    S -> C  ACK + small response (PSH-ACK) at t=1+RTT, 2+RTT, ...

Flow uses Linux-style TSopt so the TS path produces matches; the
window_start is set on packet 0 (SYN) and the cap fires twice within
a 12s replay when --flowMaxAge=5 is passed.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_000
    cip = "10.0.0.10"
    sip = "10.0.1.1"
    cport = 40000
    sport = 53
    cisn = common.isn()
    sisn = common.isn()
    cts = 1_000_000
    sts = 2_000_000

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

    # Handshake at t=0
    pkts_h = []
    pkts_h.append((C2S(cisn, 0, "S", b"", 0,
                       common.LIN_OPTS_SYN(cts)), 0.0))
    pkts_h.append((S2C(sisn, cisn + 1, "SA", b"", 1,
                       [("MSS", 1460), ("SAckOK", b""),
                        ("Timestamp", (sts, cts)),
                        ("NOP", None), ("WScale", 7)]), 0.05))
    pkts_h.append((C2S(cisn + 1, sisn + 1, "A", b"", 2,
                       common.LIN_OPTS_DATA(cts + 1, sts)), 0.10))
    for p, off in pkts_h:
        p.time = float(base_ts) + off
        pkts.append(p)

    # 12 query/response exchanges, one per second of capture-time.
    cseq = cisn + 1
    sseq = sisn + 1
    cts += 2
    sts += 1
    for i in range(1, 13):
        t = float(base_ts) + i  # +i seconds from base
        query = b"\x00\x3a" + b"\x00" * 56
        resp  = b"\x00\x4e" + b"\x00" * 76
        # query C->S
        p1 = C2S(cseq, sseq, "PA", query, 0,
                 common.LIN_OPTS_DATA(cts, sts))
        p1.time = t
        pkts.append(p1)
        # response S->C (50ms later — yields a 50ms RTT sample)
        p2 = S2C(sseq, cseq + len(query), "PA", resp, 0,
                 common.LIN_OPTS_DATA(sts, cts))
        p2.time = t + 0.050
        pkts.append(p2)
        # client ACK C->S
        p3 = C2S(cseq + len(query), sseq + len(resp), "A", b"", 0,
                 common.LIN_OPTS_DATA(cts + 1, sts))
        p3.time = t + 0.100
        pkts.append(p3)
        cseq += len(query)
        sseq += len(resp)
        cts += 2
        sts += 1

    return pkts


if __name__ == "__main__":
    common.write("age_cap.pcap", build())
