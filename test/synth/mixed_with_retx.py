"""
mixed-with-retx.pcap — 3 flows.
  A: TCP retransmission while a SEQ-path measurement is outstanding.
     SEQ path must drop that sample (seq_karn_drops++) and keep its minRTT
     untainted by the spurious "RTT" the retx would otherwise produce.
  B: clean TS-capable flow (control for ts/hybrid).
  C: clean no-TS flow (control for seq/hybrid).
"""
from . import common


def _timed(pkts, t0):
    for p, off in pkts:
        p.time = t0 + off
    return [p for p, _ in pkts]


def build():
    common.seed(20260507)
    pkts = []
    base_ts = 1_000_000_900
    W = common.WIN_OPTS_SYN

    # ----- Flow A: retx during measurement (no TSopt) -----
    C2S, S2C = common.flow("10.0.4.10", "10.0.5.1", 60000, 53)
    cisn = common.isn()
    sisn = common.isn()
    seg1 = b"X" * 100
    seg2 = b"Y" * 100
    pkts += _timed([
        (C2S(cisn,       0,              "S",  opts=W), 0.000),
        (S2C(sisn,       cisn + 1,       "SA", opts=W), 0.050),
        (C2S(cisn + 1,   sisn + 1,       "A"),          0.100),
        # First data segment opens the outstanding measurement.
        (C2S(cisn + 1,   sisn + 1,       "PA", seg1),   0.150),
        # Spurious retransmission of the same bytes before the ACK: trips retx_flag.
        (C2S(cisn + 1,   sisn + 1,       "PA", seg1),   0.180),
        # Server ACK: discarded under strict Karn.
        (S2C(sisn + 1,   cisn + 1 + 100, "A"),          0.200),
        # Clean exchange after retx_flag clears on the next outstanding.
        (C2S(cisn + 101, sisn + 1,       "PA", seg2),   0.300),
        (S2C(sisn + 1,   cisn + 201,     "A"),          0.350),
        (C2S(cisn + 201, sisn + 1,       "FA"),         0.400),
        (S2C(sisn + 1,   cisn + 202,     "FA"),         0.450),
        (C2S(cisn + 202, sisn + 2,       "A"),          0.500),
    ], float(base_ts))

    # ----- Flow B: clean TS-capable -----
    C2S, S2C = common.flow("10.0.4.20", "10.0.5.1", 60001, 53)
    cisn = common.isn(); sisn = common.isn()
    cts, sts = 333_000, 444_000
    D = common.LIN_OPTS_DATA
    pkts += _timed([
        (C2S(cisn,      0,       "S",  opts=common.LIN_OPTS_SYN(cts)),      0.000),
        (S2C(sisn,      cisn+1,  "SA", opts=common.LIN_OPTS_SYN(sts, cts)), 0.050),
        (C2S(cisn+1,    sisn+1,  "A",  opts=D(cts+1, sts)),                 0.100),
        (C2S(cisn+1,    sisn+1,  "PA", b"Q"*60, D(cts+2, sts)),             0.150),
        (S2C(sisn+1,    cisn+61, "PA", b"R"*80, D(sts+1, cts+2)),           0.200),
        (C2S(cisn+61,   sisn+81, "FA", opts=D(cts+3, sts+1)),               0.250),
        (S2C(sisn+81,   cisn+62, "FA", opts=D(sts+2, cts+3)),               0.300),
        (C2S(cisn+62,   sisn+82, "A",  opts=D(cts+4, sts+2)),               0.350),
    ], float(base_ts) + 1.0)

    # ----- Flow C: clean no-TS -----
    C2S, S2C = common.flow("10.0.4.30", "10.0.5.1", 60002, 53)
    cisn = common.isn(); sisn = common.isn()
    pkts += _timed([
        (C2S(cisn,      0,         "S",  opts=W), 0.000),
        (S2C(sisn,      cisn + 1,  "SA", opts=W), 0.050),
        (C2S(cisn + 1,  sisn + 1,  "A"),          0.100),
        (C2S(cisn + 1,  sisn + 1,  "PA", b"Q"*60), 0.150),
        (S2C(sisn + 1,  cisn + 61, "PA", b"R"*80), 0.200),
        (C2S(cisn + 61, sisn + 81, "FA"),         0.250),
        (S2C(sisn + 81, cisn + 62, "FA"),         0.300),
        (C2S(cisn + 62, sisn + 82, "A"),          0.350),
    ], float(base_ts) + 2.0)

    return pkts
