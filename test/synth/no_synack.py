"""
no_synack.pcap — single SYN packet with no SYN-ACK reply.

Exercises the n_samples=0 silent-delete path: in -a mode this should
produce zero output rows even after idle expiry. The flow has revFlow
== false throughout, so no RTT match is ever attempted.
"""
from . import common


def build():
    common.seed(20260508)
    cisn = common.isn()
    C2S, _ = common.flow("10.0.0.99", "10.0.1.1", 40099, 53)
    syn = C2S(cisn, 0, "S", opts=common.LIN_OPTS_SYN(100_000))
    syn.time = 1_000_000_000.0
    return [syn]
