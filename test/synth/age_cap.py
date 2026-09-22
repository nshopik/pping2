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
from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_000
    C2S, S2C = common.flow("10.0.0.10", "10.0.1.1", 40000, 53)
    cisn = common.isn()
    sisn = common.isn()
    cts = 1_000_000
    sts = 2_000_000
    D = common.LIN_OPTS_DATA

    # Handshake at t=0
    for p, off in [
        (C2S(cisn, 0, "S", opts=common.LIN_OPTS_SYN(cts)), 0.0),
        (S2C(sisn, cisn + 1, "SA", opts=common.LIN_OPTS_SYN(sts, cts)), 0.05),
        (C2S(cisn + 1, sisn + 1, "A", opts=D(cts + 1, sts)), 0.10),
    ]:
        p.time = float(base_ts) + off
        pkts.append(p)

    # 12 query/response exchanges, one per second of capture-time.
    cseq = cisn + 1
    sseq = sisn + 1
    cts += 2
    sts += 1
    query = b"\x00\x3a" + b"\x00" * 56
    resp = b"\x00\x4e" + b"\x00" * 76
    for i in range(1, 13):
        t = float(base_ts) + i
        # query, response 50ms later (one 50ms RTT sample), client ACK
        for p, off in [
            (C2S(cseq, sseq, "PA", query, D(cts, sts)), 0.0),
            (S2C(sseq, cseq + len(query), "PA", resp, D(sts, cts)), 0.050),
            (C2S(cseq + len(query), sseq + len(resp), "A",
                 opts=D(cts + 1, sts)), 0.100),
        ]:
            p.time = t + off
            pkts.append(p)
        cseq += len(query)
        sseq += len(resp)
        cts += 2
        sts += 1

    return pkts
