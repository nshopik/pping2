"""
mixed-with-retx.pcap — 3 flows.
  A: TCP retransmission while a SEQ-path measurement is outstanding.
     SEQ path must drop that sample (seq_karn_drops++) and keep its minRTT
     untainted by the spurious "RTT" the retx would otherwise produce.
  B: clean TS-capable flow (control for ts/hybrid).
  C: clean no-TS flow (control for seq/hybrid).
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260507)
    pkts = []
    base_ts = 1_000_000_900

    # ----- Flow A: retx during measurement (no TSopt) -----
    cip, sip = "10.0.4.10", "10.0.5.1"
    cport, sport = 60000, 53
    cisn = common.isn()
    sisn = common.isn()
    t0 = float(base_ts)

    def E_C2S(seq, ack, flags, payload, opts=None):
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    def E_S2C(seq, ack, flags, payload, opts=None):
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    # 3-way handshake
    pkts.append(E_C2S(cisn,        0,           "S",  b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0
    pkts.append(E_S2C(sisn,        cisn + 1,    "SA", b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0 + 0.050
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "A",  b""));                          pkts[-1].time = t0 + 0.100
    # First data segment C->S, 100 bytes -- opens the outstanding measurement
    seg1 = b"X" * 100
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "PA", seg1));                         pkts[-1].time = t0 + 0.150
    # Spurious retransmission of the SAME bytes BEFORE the ACK arrives. This
    # must trip retx_flag.
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "PA", seg1));                         pkts[-1].time = t0 + 0.180
    # Server ACK arrives -- under strict Karn this match is discarded.
    pkts.append(E_S2C(sisn + 1,    cisn + 1 + 100, "A",  b""));                       pkts[-1].time = t0 + 0.200
    # Followup clean exchange (after retx_flag clears on next outstanding).
    seg2 = b"Y" * 100
    pkts.append(E_C2S(cisn + 101,  sisn + 1,    "PA", seg2));                         pkts[-1].time = t0 + 0.300
    pkts.append(E_S2C(sisn + 1,    cisn + 201,  "A",  b""));                          pkts[-1].time = t0 + 0.350
    # Teardown
    pkts.append(E_C2S(cisn + 201,  sisn + 1,    "FA", b""));                          pkts[-1].time = t0 + 0.400
    pkts.append(E_S2C(sisn + 1,    cisn + 202,  "FA", b""));                          pkts[-1].time = t0 + 0.450
    pkts.append(E_C2S(cisn + 202,  sisn + 2,    "A",  b""));                          pkts[-1].time = t0 + 0.500

    # ----- Flow B: clean TS-capable -----
    cip, sip = "10.0.4.20", "10.0.5.1"
    cport, sport = 60001, 53
    cisn = common.isn(); sisn = common.isn()
    t0 = float(base_ts) + 1.0
    cts, sts = 333_000, 444_000

    def L_C2S(seq, ack, flags, payload, tsval, tsecr):
        opts = [("NOP", None), ("NOP", None), ("Timestamp", (tsval, tsecr))]
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts) / \
               (Raw(load=payload) if payload else b"")

    def L_S2C(seq, ack, flags, payload, tsval, tsecr):
        opts = [("NOP", None), ("NOP", None), ("Timestamp", (tsval, tsecr))]
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts) / \
               (Raw(load=payload) if payload else b"")

    # SYN with TSopt
    syn_opts = common.LIN_OPTS_SYN(cts)
    pkts.append(Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) /
                IP(src=cip, dst=sip) /
                TCP(sport=cport, dport=sport, seq=cisn, ack=0, flags="S", options=syn_opts));    pkts[-1].time = t0
    synack_opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (sts, cts)),
                   ("NOP", None), ("WScale", 7)]
    pkts.append(Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) /
                IP(src=sip, dst=cip) /
                TCP(sport=sport, dport=cport, seq=sisn, ack=cisn+1, flags="SA", options=synack_opts)); pkts[-1].time = t0 + 0.050
    pkts.append(L_C2S(cisn+1, sisn+1, "A",  b"",       cts+1, sts));   pkts[-1].time = t0 + 0.100
    pkts.append(L_C2S(cisn+1, sisn+1, "PA", b"Q"*60,  cts+2, sts));    pkts[-1].time = t0 + 0.150
    pkts.append(L_S2C(sisn+1, cisn+61, "PA", b"R"*80,  sts+1, cts+2)); pkts[-1].time = t0 + 0.200
    pkts.append(L_C2S(cisn+61, sisn+81, "FA", b"",     cts+3, sts+1)); pkts[-1].time = t0 + 0.250
    pkts.append(L_S2C(sisn+81, cisn+62, "FA", b"",     sts+2, cts+3)); pkts[-1].time = t0 + 0.300
    pkts.append(L_C2S(cisn+62, sisn+82, "A",  b"",     cts+4, sts+2)); pkts[-1].time = t0 + 0.350

    # ----- Flow C: clean no-TS -----
    cip, sip = "10.0.4.30", "10.0.5.1"
    cport, sport = 60002, 53
    cisn = common.isn(); sisn = common.isn()
    t0 = float(base_ts) + 2.0

    def W_C2S(seq, ack, flags, payload, opts=None):
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    def W_S2C(seq, ack, flags, payload, opts=None):
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    pkts.append(W_C2S(cisn,     0,         "S",  b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0
    pkts.append(W_S2C(sisn,     cisn + 1,  "SA", b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0 + 0.050
    pkts.append(W_C2S(cisn + 1, sisn + 1,  "A",  b""));                          pkts[-1].time = t0 + 0.100
    pkts.append(W_C2S(cisn + 1, sisn + 1,  "PA", b"Q"*60));                      pkts[-1].time = t0 + 0.150
    pkts.append(W_S2C(sisn + 1, cisn + 61, "PA", b"R"*80));                      pkts[-1].time = t0 + 0.200
    pkts.append(W_C2S(cisn + 61, sisn + 81, "FA", b""));                         pkts[-1].time = t0 + 0.250
    pkts.append(W_S2C(sisn + 81, cisn + 62, "FA", b""));                         pkts[-1].time = t0 + 0.300
    pkts.append(W_C2S(cisn + 62, sisn + 82, "A",  b""));                         pkts[-1].time = t0 + 0.350

    return pkts


if __name__ == "__main__":
    common.write("mixed-with-retx.pcap", build())
