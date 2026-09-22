"""
dns-tcp-windows.pcap — 5 DNS-over-TCP flows (Windows client), no TSopt.
Same packet shape and timing as dns-tcp-linux but TCP options are MSS +
WScale + SACK-Permitted (no Timestamp). Validates the SEQ path's headline
use case: hybrid mode produces samples, ts mode drops them as no_TS.
"""
from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_500

    for i in range(5):
        C2S, S2C = common.flow(f"10.0.2.{10 + i}", "10.0.3.1", 50000 + i, 53)
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0
        query = b"\x00\x3a" + b"\x00" * 56
        resp = b"\x00\x4e" + b"\x00" * 76

        steps = [
            C2S(cisn, 0, "S", opts=common.WIN_OPTS_SYN),
            S2C(sisn, cisn + 1, "SA", opts=common.WIN_OPTS_SYN),
            C2S(cisn + 1, sisn + 1, "A"),
            C2S(cisn + 1, sisn + 1, "PA", query),
            S2C(sisn + 1, cisn + 1 + len(query), "A"),
            S2C(sisn + 1, cisn + 1 + len(query), "PA", resp),
            C2S(cisn + 1 + len(query), sisn + 1 + len(resp), "A"),
            C2S(cisn + 1 + len(query), sisn + 1 + len(resp), "FA"),
            S2C(sisn + 1 + len(resp), cisn + 2 + len(query), "FA"),
            C2S(cisn + 2 + len(query), sisn + 2 + len(resp), "A"),
        ]
        for step, pkt in enumerate(steps):
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts
