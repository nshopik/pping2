# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Building

```sh
make
```

Requires [libtins](http://libtins.github.io/) installed at `~/src/libtins`. If installed elsewhere (e.g. system-wide via package manager), override with:

```sh
make LIBTINS=/usr/local
```

Also requires `libpcap`. No test suite exists; validation is done by running against a live interface or pcap file.

## Running

```sh
# Live capture (requires root/cap_net_raw)
sudo ./pping -i eth0

# From pcap file
./pping -r capture.pcap

# Machine-readable output (compact)
./pping -m -i eth0

# Extended machine-readable output (all fields)
./pping -e -i eth0
```

## Architecture

Single-file C++ program (`pping.cpp`) using [libtins](http://libtins.github.io/) for packet parsing and libpcap for capture.

**Core data structures:**
- `flowRec` — per-flow state: min RTT, byte counters, whether a reverse flow has been seen
- `tsInfo` — records the capture time and byte counts when a TSval was first seen
- `flows` map — keyed by `srcIP:sport+dstIP:dport`
- `tsTbl` map — keyed by `flow+TSval`; stores `tsInfo` for matching against ECR

**RTT measurement loop (`process_packet`):**
1. Extract TSval and ECR from TCP timestamp option
2. Look up `flow+ECR` in `tsTbl` against the *reverse* flow's saved TSvals
3. If matched: `RTT = now - saved_capture_time`; update flow min; emit output line
4. Save current TSval in `tsTbl` (only if reverse flow is known, to avoid one-directional state)
5. `cleanUp()` periodically evicts stale TSvals (older than `tsvalMaxAge`) and idle flows

**Output:** all RTT lines go to stdout; summary/diagnostic stats go to stderr. Three formats:
- **Human-readable** (default): `HH:MM:SS <rtt> <minRTT> srcIP:sport+dstIP:dport`
- **Machine-readable** (`-m`): `unix_timestamp.usec rtt_sec srcIP dstIP`
- **Extended machine-readable** (`-e`): `unix_timestamp.usec rtt_sec minRTT_sec fBytes dBytes pBytes srcIP sport dstIP dport node`

`-e` implies `-m`. stdout is flushed periodically via `flushInt` (every ~1s normally, ~100ms in live+machine-readable mode).
