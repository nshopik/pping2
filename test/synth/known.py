"""known.pcap — the minimal deterministic TS-path fixture.

Six packets of one IPv4 TCP session, 50 ms apart, every packet carrying a TCP
timestamp option. Client TSvals run 1000, 1001, 1002; server 2000, 2001, 2002.
Each ECR matches the previous packet in the other direction, so pping reports
exactly four RTT samples of 0.050000 s.

Consumed by test_integration.sh (golden diff) and test_cli.sh.
"""
from decimal import Decimal

from . import common

BASE_TIME = Decimal("1000000000")   # 2001-09-08 21:46:40 UTC
STEP = Decimal("0.05")

PAYLOAD = b"hello world!\n"

# (src_is_client, seq, ack, flags, tsval, tsecr, payload)
PACKETS = [
    (True,   100,    0, "S",  1000,    0, b""),
    (False, 5000,  101, "SA", 2000, 1000, b""),
    (True,   101, 5001, "A",  1001, 2000, b""),
    (False, 5001,  102, "PA", 2001, 1001, PAYLOAD),
    (True,   102, 5014, "PA", 1002, 2001, PAYLOAD),
    (False, 5014,  115, "PA", 2002, 1002, PAYLOAD),
]


def build():
    C2S, S2C = common.flow("10.0.0.1", "10.0.0.2", 1234, 80)
    pkts = []
    for i, (from_client, seq, ack, flags, tsval, tsecr, payload) in enumerate(PACKETS):
        pkt = (C2S if from_client else S2C)(seq, ack, flags, payload,
                                           common.LIN_OPTS_DATA(tsval, tsecr))
        pkt.time = BASE_TIME + i * STEP
        pkts.append(pkt)
    return pkts
