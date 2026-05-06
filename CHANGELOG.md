# Changelog

## Unreleased

### Added

- `-a` / `--aggregate` output mode: one row per flow per closure-or-window
  event instead of one row per RTT match. Nine fields:
  `epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag`.
  Designed for direct ingestion into ClickHouse where downstream
  aggregation only consumes per-flow `min` RTT.
- `--flowMaxAge=<sec>` (default 1800, 0=disabled) caps how long a single
  flow's accumulator can run before emitting a row and resetting.
- Two new summary-line counters: `aggregated rows,` and
  `flows dropped (cap),`.

### Changed

- `maxFlows` default raised from 65535 to 1,048,576 (`1024^2`). Memory at
  full cap ~170 MB combined; trivial on any host running ClickHouse.
- `maxTSvals` default raised from 4,000,000 to 268,435,456 (`16^7`).
  Worst-case ~74 GB IPv6; real workloads at 1 Mpps stay single-digit GB.
- The per-rejection `flow limit (...) reached, dropping new flow:` stderr
  line is removed; rejections are counted in `flows dropped (cap),`.
- **Default RTT measurement now uses hybrid TS+SEQ path** (`--mode hybrid`).
  Flows previously dropped as `no_TS` (Windows, stripped-TS middleboxes) now
  produce SEQ-path samples. To restore prior behavior pass `--mode ts`.

### Added (mode/SEQ work)

- `--mode {ts,seq,hybrid}` CLI flag selects the RTT measurement path.
- SEQ/ACK-based RTT path. Tracks one outstanding measurement per flow
  direction; strict Karn discards samples whose forward window was
  retransmitted.
- 12th field on `-e` extended output: `t` (TS path) or `s` (SEQ path).
- `[t]`/`[s]` tag on human-readable output.
- Summary counters: `seq samples` (production), `seq karn drops`, `seq stale`
  (diagnostic; printed only when non-zero).
- Test fixtures `dns-tcp-linux.pcap`, `dns-tcp-windows.pcap`,
  `mixed-with-retx.pcap` synthesized via `make pcaps` (requires scapy).
- Cross-mode parity test asserts `--mode ts` and `--mode hybrid` produce
  bit-identical output on TS-capable workloads.
- `test/bench.sh` for ad-hoc per-mode throughput comparisons.

### Notes

- `-m` (compact machine output) is unchanged byte-for-byte.
- TS path is preserved bit-for-bit on TS-capable flows in both `--mode ts` and
  `--mode hybrid`.
