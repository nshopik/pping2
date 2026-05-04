#!/usr/bin/env python
"""
gen_pcap.py — generate test/known.pcap
A synthetic bidirectional TCP session with TCP timestamp options,
designed so pping produces deterministic RTT values.

Pcap format written manually (no scapy dependency).

Packet layout (Ethernet II / IPv4 / TCP):
  14 bytes Ethernet
  20 bytes IPv4 (no options)
  TCP header with one TCP timestamp option (10 bytes) + NOP padding
    TCP option layout:
      1 byte  NOP  (0x01)
      1 byte  NOP  (0x01)
      1 byte  kind=8 (Timestamp)
      1 byte  len=10
      4 bytes TSval (big-endian)
      4 bytes TSecr (big-endian)
    = 10 bytes of options + 2 NOPs = 12 bytes total option space
  TCP data_offset = (20 + 12) / 4 = 8  (i.e. 32-byte TCP header)

IPs:
  Client: 10.0.0.1  port 1234
  Server: 10.0.0.2  port 80

Packet timeline (base_sec = 1_000_000_000 for a plausible epoch):
  Each packet is 50ms apart.

  Pkt  Time(s)  Dir    Flags       TSval  TSecr  Notes
  ---  -------  -----  ----------  -----  -----  ------
   0   +0.000   C→S    SYN         1000      0   pping skips (revFlow false)
   1   +0.050   S→C    SYN-ACK     2000   1000   pping stores TSval=2000; ECR=1000 not found
   2   +0.100   C→S    ACK         1001   2000   RTT[0]=0.050000 (C→S, ECR matches pkt1)
   3   +0.150   S→C    PSH|ACK     2001   1001   RTT[1]=0.050000 (S→C, ECR matches pkt2)
   4   +0.200   C→S    PSH|ACK     1002   2001   RTT[2]=0.050000 (C→S, ECR matches pkt3)
   5   +0.250   S→C    PSH|ACK     2002   1002   RTT[3]=0.050000 (S→C, ECR matches pkt4)

Expected pping -m output (4 lines, RTT column = 0.050000):
  1000000000.100000 0.050000 10.0.0.1 10.0.0.2
  1000000000.150000 0.050000 10.0.0.2 10.0.0.1
  1000000000.200000 0.050000 10.0.0.1 10.0.0.2
  1000000000.250000 0.050000 10.0.0.2 10.0.0.1

(srcIP/dstIP columns reflect the packet that triggers the RTT measurement,
 i.e. the returning packet's source and destination.)
"""

import struct
import os

# ---------------------------------------------------------------------------
# pcap file format helpers
# ---------------------------------------------------------------------------

PCAP_MAGIC    = 0xa1b2c3d4   # native-endian, microsecond resolution
PCAP_VMAJ     = 2
PCAP_VMIN     = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS  = 0
PCAP_SNAPLEN  = 65535
PCAP_NETWORK  = 1            # LINKTYPE_ETHERNET


def pcap_global_header():
    """24-byte global file header."""
    return struct.pack('<IHHiIII',
                       PCAP_MAGIC, PCAP_VMAJ, PCAP_VMIN,
                       PCAP_THISZONE, PCAP_SIGFIGS,
                       PCAP_SNAPLEN, PCAP_NETWORK)


def pcap_record_header(ts_sec, ts_usec, pkt_len):
    """16-byte per-packet record header."""
    return struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len)


# ---------------------------------------------------------------------------
# checksum
# ---------------------------------------------------------------------------

def checksum(data):
    """Standard internet checksum over bytes-like object."""
    if len(data) % 2:
        data = data + b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# ---------------------------------------------------------------------------
# Ethernet header
# ---------------------------------------------------------------------------

CLIENT_MAC = b'\x00\x00\x00\x00\x00\x01'
SERVER_MAC = b'\x00\x00\x00\x00\x00\x02'
ETHERTYPE_IP = b'\x08\x00'

def eth_header(src_mac, dst_mac):
    return dst_mac + src_mac + ETHERTYPE_IP   # 14 bytes


# ---------------------------------------------------------------------------
# IPv4 header  (20 bytes, no options)
# ---------------------------------------------------------------------------

CLIENT_IP = b'\x0a\x00\x00\x01'   # 10.0.0.1
SERVER_IP = b'\x0a\x00\x00\x02'   # 10.0.0.2


def ipv4_header(src_ip, dst_ip, proto, payload_len):
    """Build a 20-byte IPv4 header with correct checksum."""
    total_len = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH4s4s',
                      0x45,           # version=4, IHL=5
                      0,              # DSCP/ECN
                      total_len,
                      0,              # identification
                      0,              # flags + fragment offset
                      64,             # TTL
                      proto,          # protocol (6 = TCP)
                      0,              # checksum placeholder
                      src_ip,
                      dst_ip)
    csum = checksum(hdr)
    # patch checksum at byte offset 10
    return hdr[:10] + struct.pack('>H', csum) + hdr[12:]


# ---------------------------------------------------------------------------
# TCP header  (20 bytes fixed + 12 bytes options = 32 bytes total)
#
# Option layout (12 bytes):
#   0x01          NOP
#   0x01          NOP
#   0x08 0x0a     kind=8, len=10
#   <tsval 4B>
#   <tsecr 4B>
# ---------------------------------------------------------------------------

TCP_HDR_LEN = 32   # with timestamp option


def tcp_segment(src_port, dst_port, seq, ack, flags, tsval, tsecr, payload=b''):
    """
    Build TCP segment (header + options + payload) with correct checksum.
    flags: integer bitmask (SYN=0x02, ACK=0x10, PSH=0x08, RST=0x04, FIN=0x01)
    """
    # TCP options: NOP NOP TIMESTAMP(10)
    options = struct.pack('>BB', 0x01, 0x01)          # two NOPs
    options += struct.pack('>BBII', 0x08, 0x0a, tsval, tsecr)  # kind len tsval tsecr
    # data offset = (20 + 12) / 4 = 8
    data_offset = (TCP_HDR_LEN // 4) << 4

    hdr = struct.pack('>HHIIBBHHH',
                      src_port,
                      dst_port,
                      seq,
                      ack,
                      data_offset,
                      flags,
                      65535,          # window size
                      0,              # checksum placeholder
                      0)              # urgent pointer
    return hdr + options + payload


def build_tcp_with_checksum(src_ip, dst_ip,
                             src_port, dst_port,
                             seq, ack, flags,
                             tsval, tsecr,
                             payload=b''):
    """Return complete TCP segment with correct checksum."""
    segment = tcp_segment(src_port, dst_port, seq, ack, flags,
                          tsval, tsecr, payload)
    # pseudo-header for checksum
    pseudo = struct.pack('>4s4sBBH',
                         src_ip, dst_ip,
                         0,
                         6,                   # TCP protocol number
                         len(segment))
    csum = checksum(pseudo + segment)
    # checksum is at byte offset 16 in the TCP header
    return segment[:16] + struct.pack('>H', csum) + segment[18:]


# ---------------------------------------------------------------------------
# Build a full Ethernet/IPv4/TCP packet
# ---------------------------------------------------------------------------

def build_packet(src_mac, dst_mac,
                 src_ip, dst_ip,
                 src_port, dst_port,
                 seq, ack, flags,
                 tsval, tsecr,
                 payload=b''):
    tcp = build_tcp_with_checksum(src_ip, dst_ip,
                                   src_port, dst_port,
                                   seq, ack, flags,
                                   tsval, tsecr, payload)
    ip  = ipv4_header(src_ip, dst_ip, 6, len(tcp))
    eth = eth_header(src_mac, dst_mac)
    return eth + ip + tcp


# ---------------------------------------------------------------------------
# Packet definitions
# ---------------------------------------------------------------------------

# Ports
C_PORT = 1234
S_PORT = 80

# TCP flag constants
SYN     = 0x02
ACK     = 0x10
SYNACK  = SYN | ACK
PSHACK  = 0x08 | ACK

# Base timestamp: 1_000_000_000 seconds since epoch (2001-09-08 21:46:40 UTC)
BASE_SEC  = 1_000_000_000
BASE_USEC = 0
STEP_USEC = 50_000   # 50 ms = 50000 microseconds

def ts(pkt_index):
    """Return (sec, usec) for packet at index i (0-based)."""
    total_usec = BASE_USEC + pkt_index * STEP_USEC
    return BASE_SEC + total_usec // 1_000_000, total_usec % 1_000_000


# Packet list: (pkt_index, src_mac, dst_mac, src_ip, dst_ip, sport, dport,
#               seq, ack, flags, tsval, tsecr, payload)
#
# TSvals:
#   Client uses 1000, 1001, 1002, …
#   Server uses 2000, 2001, 2002, …
#
# SEQ/ACK: simplified (pping doesn't use them for RTT; checksums just need to be valid)

PAYLOAD_DATA = b'hello world!\n'   # 13 bytes

packets = [
    # idx   smac        dmac        sip        dip        sp      dp      seq   ack   flags   tsval  tsecr  payload
    (0,  CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, C_PORT, S_PORT,   100,    0, SYN,     1000,     0, b''),
    (1,  SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, S_PORT, C_PORT,  5000,  101, SYNACK,  2000,  1000, b''),
    (2,  CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, C_PORT, S_PORT,   101,  5001, ACK,    1001,  2000, b''),
    (3,  SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, S_PORT, C_PORT,  5001,   102, PSHACK, 2001,  1001, PAYLOAD_DATA),
    (4,  CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, C_PORT, S_PORT,   102,  5014, PSHACK, 1002,  2001, PAYLOAD_DATA),
    (5,  SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, S_PORT, C_PORT,  5014,   115, PSHACK, 2002,  1002, PAYLOAD_DATA),
]


# ---------------------------------------------------------------------------
# Write pcap
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path   = os.path.join(script_dir, 'known.pcap')

    with open(out_path, 'wb') as f:
        f.write(pcap_global_header())

        for (idx, smac, dmac, sip, dip, sport, dport,
             seq, ack, flags, tsval, tsecr, payload) in packets:

            raw = build_packet(smac, dmac, sip, dip,
                               sport, dport,
                               seq, ack, flags,
                               tsval, tsecr, payload)
            sec, usec = ts(idx)
            f.write(pcap_record_header(sec, usec, len(raw)))
            f.write(raw)

    file_size = os.path.getsize(out_path)
    print(f"Written: {out_path}")
    print(f"Size:    {file_size} bytes")
    print(f"Packets: {len(packets)}")
    return out_path, file_size


if __name__ == '__main__':
    main()
