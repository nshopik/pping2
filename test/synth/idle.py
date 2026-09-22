"""
idle.pcap — two flows that exercise --flowMaxIdle in -a mode.

Flow A: packets at t=0, +0.05 (RTT match). Goes silent.
Flow B: packets at t=8, +8.05 (one RTT match), keeps the capture clock
        moving so cleanUp gets called past the idle threshold.

Run with --tsvalMaxAge=1 --flowMaxIdle=2 -a: cleanUp at t~=8 evicts
Flow A (idle = 8 - 0.05 = 7.95 > 2) and emits its row using
last_tm = 0.05, NOT capTm = 8.
"""
from . import common


def _exchange(cip, sip, cport, sport, base_t, cts0, sts0):
    C2S, S2C = common.flow(cip, sip, cport, sport)
    cisn = common.isn()
    sisn = common.isn()
    out = []
    # SYN, SYN-ACK, ACK
    for p, off in [
        (C2S(cisn, 0, "S", opts=common.LIN_OPTS_SYN(cts0)), 0.000),
        (S2C(sisn, cisn + 1, "SA", opts=common.LIN_OPTS_SYN(sts0, cts0)), 0.025),
        (C2S(cisn + 1, sisn + 1, "A", opts=common.LIN_OPTS_DATA(cts0 + 1, sts0)), 0.050),
    ]:
        p.time = base_t + off
        out.append(p)
    return out


def build():
    common.seed(20260507)
    # Flow A at t=0..0.05; flow B at t=8..8.05 keeps the capture clock
    # advancing past flow A's idle threshold.
    return (_exchange("10.0.0.10", "10.0.1.1", 40000, 53,
                      base_t=1_000_000_000, cts0=100_000, sts0=200_000)
            + _exchange("10.0.0.20", "10.0.1.1", 40001, 53,
                        base_t=1_000_000_008, cts0=300_000, sts0=400_000))
