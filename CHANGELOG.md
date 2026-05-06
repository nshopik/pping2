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
- `--logfile=PATH` flag in pping: open the path with append+create as
  stdout, and reopen on SIGHUP. Enables zero-copy atomic log rotation
  by external tools (`mv old new; kill -HUP $pid`). Without `--logfile`,
  behavior is unchanged.
- Bundled systemd unit (`contrib/systemd/pping.service`) with
  `ExecReload=/bin/kill -HUP $MAINPID` for log rotation, and shared
  environment file (`/etc/default/pping`). Single-interface in v1;
  multi-interface and per-row interface attribution will land together
  in a future release.
- Bundled ClickHouse loader (`contrib/clickhouse/`) — batch-load script,
  cron entry, and `pping_flows` table schema matching `-a` output.
  Loader rotates via atomic `mv` + `systemctl reload pping.service`.
  Two ingest paths: `clickhouse-client` (default) speaks the native TCP
  protocol; `curl` uses the HTTP interface and needs no extra packages
  on the capture host. Selected via `PPING_INGEST` in `/etc/default/pping`.
- Makefile `install`, `install-systemd`, `install-clickhouse`,
  `install-all` targets and matching `uninstall*` targets. `DESTDIR` and
  `PREFIX` honored for distro packagers; `setcap` is skipped with a
  warning when `DESTDIR` is set. Install-time `sed` substitutes
  `PREFIX`/`SYSCONFDIR` into shipped scripts and unit files so non-default
  installs (e.g. `PREFIX=/usr`) produce a coherent layout.
- Quickstart-shaped `clickhouse.md` documenting install → edit env file →
  apply schema → enable service end-to-end. `deploy.md` removed (its
  content folded in).

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
