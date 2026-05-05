# Changelog

## Unreleased

### Changed

- **Default RTT measurement now uses hybrid TS+SEQ path** (`--mode hybrid`).
  Flows previously dropped as `no_TS` (Windows, stripped-TS middleboxes) now
  produce SEQ-path samples. To restore prior behavior pass `--mode ts`.

### Added

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
