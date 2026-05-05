"""
Shared helpers for synthesized RTT-test pcaps.

All synth modules use a fixed RNG seed so ISNs are deterministic and golden
output is reproducible. Each module defines `build()` that returns a list of
scapy packets and writes the pcap via `write(name, pkts)` below.
"""
import os
import random
from pathlib import Path

from scapy.all import (
    Ether, IP, TCP, Raw, wrpcap,
)

PCAPS_DIR = Path(__file__).resolve().parent.parent / "pcaps"

# Stable MACs and IPs across all fixtures.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"

# The 50ms RTT in linux/windows fixtures matches the existing test/known.pcap
# convention so a future cross-fixture regression is easy to eyeball.
RTT_SEC = 0.050

# Windows-style TCP options on the SYN: MSS, SACK-Permitted, Window Scale.
# Order chosen to match what Windows 10 actually emits on TCP SYN.
WIN_OPTS_SYN = [("MSS", 1460), ("NOP", None), ("WScale", 8),
                ("NOP", None), ("NOP", None), ("SAckOK", b"")]
WIN_OPTS_ACK = []  # post-handshake: no options on data packets

# Linux-style TCP options on the SYN: MSS, SACK-Permitted, Timestamp, NOP, WScale.
LIN_OPTS_SYN = lambda tsval: [
    ("MSS", 1460), ("SAckOK", b""),
    ("Timestamp", (tsval, 0)), ("NOP", None), ("WScale", 7),
]
LIN_OPTS_DATA = lambda tsval, tsecr: [
    ("NOP", None), ("NOP", None), ("Timestamp", (tsval, tsecr)),
]


def seed(value: int) -> None:
    random.seed(value)


def isn() -> int:
    return random.randint(1, 2**31 - 1)


def write(name: str, pkts) -> Path:
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)
    path = PCAPS_DIR / name
    wrpcap(str(path), pkts)
    return path
