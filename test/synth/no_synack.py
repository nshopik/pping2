"""
no_synack.pcap — single SYN packet with no SYN-ACK reply.

Exercises the n_samples=0 silent-delete path: in -a mode this should
produce zero output rows even after idle expiry. The flow has revFlow
== false throughout, so no RTT match is ever attempted.
"""
from scapy.all import Ether, IP, TCP

from . import common


def build():
    common.seed(20260508)
    cisn = common.isn()
    syn = Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
          IP(src="10.0.0.99", dst="10.0.1.1") / \
          TCP(sport=40099, dport=53, seq=cisn, ack=0,
              flags="S", options=common.LIN_OPTS_SYN(100_000))
    syn.time = 1_000_000_000.0
    return [syn]


if __name__ == "__main__":
    common.write("no_synack.pcap", build())
