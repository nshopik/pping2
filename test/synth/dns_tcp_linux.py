"""
dns-tcp-linux.pcap — 5 DNS-over-TCP flows (Linux client → resolver), TSopt present.
Each flow: SYN, SYN-ACK, ACK, query (PSH-ACK), server ACK, response (PSH-ACK),
client ACK, FIN, FIN-ACK, ACK. ~10 packets * 5 flows = 50 packets.
Each packet is RTT_SEC apart so RTT samples are 0.050000 in golden output.
"""
from . import common


def build():
    common.seed(20260505)
    pkts = []
    base_ts = 1_000_000_000  # epoch seconds for first packet
    base_tsval_c = 100_000   # client TSval starts here, +1 per pkt
    base_tsval_s = 200_000   # server TSval

    for i in range(5):
        C2S, S2C = common.flow(f"10.0.0.{10 + i}", "10.0.1.1", 40000 + i, 53)
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0  # space flows 1s apart

        # Client TSval increments per packet sent
        cts = base_tsval_c + i * 100
        sts = base_tsval_s + i * 100
        D = common.LIN_OPTS_DATA
        query = b"\x00\x3a" + b"\x00" * 56
        resp = b"\x00\x4e" + b"\x00" * 76

        # Packet n goes out at t + n*RTT, so query→response RTT = RTT_SEC.
        steps = [
            C2S(cisn, 0, "S", opts=common.LIN_OPTS_SYN(cts)),
            S2C(sisn, cisn + 1, "SA", opts=common.LIN_OPTS_SYN(sts, cts)),
            C2S(cisn + 1, sisn + 1, "A", opts=D(cts + 1, sts)),
            C2S(cisn + 1, sisn + 1, "PA", query, D(cts + 2, sts)),
            S2C(sisn + 1, cisn + 1 + len(query), "A", opts=D(sts + 1, cts + 2)),
            S2C(sisn + 1, cisn + 1 + len(query), "PA", resp, D(sts + 2, cts + 2)),
            C2S(cisn + 1 + len(query), sisn + 1 + len(resp), "A",
                opts=D(cts + 3, sts + 2)),
            C2S(cisn + 1 + len(query), sisn + 1 + len(resp), "FA",
                opts=D(cts + 4, sts + 2)),
            S2C(sisn + 1 + len(resp), cisn + 2 + len(query), "FA",
                opts=D(sts + 3, cts + 4)),
            C2S(cisn + 2 + len(query), sisn + 2 + len(resp), "A",
                opts=D(cts + 5, sts + 3)),
        ]
        for step, pkt in enumerate(steps):
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts
