# Changelog

pping2 is a fork of [Pollere's pping](https://github.com/pollere/pping),
started at upstream commit
[`6cc6a604`](https://github.com/pollere/pping/commit/6cc6a604916d29415bd2c8f51f8be8900f6c83c8).
This is the first versioned release of the fork.

## Unreleased

## v1.2.2 — 2026-07-09

### Added

- **`PPING_FILTER` knob** in `/etc/default/pping2` — a pcap capture filter
  (may contain spaces; ANDed onto the built-in `tcp` filter). Empty by
  default (all TCP); set `port 53` to scope capture to DNS-over-TCP.
- ClickHouse write-only ingest user (`contrib/clickhouse/ingest-user.sql`),
  wired into `make install-clickhouse`.
- systemd netns override example
  (`contrib/systemd/pping2-netns-override.conf.example`) for running
  pping2 inside an existing network namespace via `NetworkNamespacePath=`.

### Changed

- **Breaking:** `pping2.service` now runs as a dedicated `pping2` system
  user/group instead of the shared `nobody` UID (systemd flags `nobody` as
  unsafe — it collides with NFS's anonymous UID and any other service also
  confined to it). `make install-systemd` and the `.deb` postinst create
  the user and chown `/var/log/pping2` to it. Hosts upgrading in place
  need `/var/log/pping2` re-chowned; the postinst/Makefile handle this
  automatically on install/upgrade.
- `pping2-load.sh` now retries a stale `.load` file left by a failed
  ingest on every cron tick instead of blocking forever until an operator
  clears it by hand.

## v1.2.1 — 2026-07-09

### Added

- **Debian 12 (bookworm) `.deb` packages** (amd64, arm64), libtins linked
  statically since bookworm has no libtins 4.5 package.

## v1.2.0 — 2026-07-02

### Changed

- Replaced `std::unordered_map` with `ankerl::unordered_dense` (vendored
  single-header) for the two hot maps `flows` and `tsTbl`. Output is
  byte-identical. Interleaved 20-iter median ns/pkt on `~/bench.pcap`
  (4M pkts, ~590K flows):

  | mode | std | unordered_dense | Δ |
  |---|---|---|---|
  | -a hybrid | 730.2 | 650.4 | −10.9% |
  | -m hybrid | 1087.1 | 946.8 | −12.9% |
  | -e hybrid | 1493.8 | 1352.6 | −9.5% |

  Real-kernel `perf stat` on `-a hybrid`: cache-misses 62.7M → 27.6M (−56%),
  peak RSS 9880 → 9264 kB (−6%).
- Set the libpcap capture ring buffer to 16 MB (`set_buffer_size`). The
  ~2 MB default holds only a few thousand frames at 10G line rate; a
  packet-loop stall then overflows the ring and drops packets silently.
  No effect on pcap replay.
- `addTS` no longer does a second `tsTbl.find()` on the cap-rejection path.
  `tsDropped` now counts all packets rejected at the `maxTSvals` cap rather
  than only those with a previously-unseen key.

### Added

- `make pgo` — two-phase profile-guided build. Instruments, trains across
  all three modes on `$BENCH_PCAP` (or `~/bench.pcap`), then rebuilds with
  the profile. Refuses to train on the small synth fixtures.
- Live capture prints a cumulative `capture: <recv> recv, <drop> drop,
  <ifdrop> ifdrop (<x>% loss)` line to stderr at shutdown, from libpcap
  `pcap_stats`. Surfaces kernel capture-ring loss (packets dropped before
  pping sees them), which biases measured RTT high. No-op in pcap replay.
  `ifdrop` is reported raw (most Linux NIC drivers never set it).

## v1.1.2 — 2026-05-24

### Added

- Static musl aarch64 tarball (`pping2-<v>-linux-aarch64-musl-static.tar.gz`)
  — drop-in binary with no shared-library or libc dependency. Targets
  OpenWrt and other musl systems.
- `--version` / `-V` flag. Version is baked into the binary at build time
  (`git describe` → `VERSION` file → `unknown`).

### Changed

- LTO (`-flto=auto`) enabled in the default build. ~7% reduction in
  per-packet cost on the reference bench (`-a hybrid`).
- `.deb` now declares `libtins4.5` in `Depends:`, so
  `sudo apt install ./pping2_<v>_<distro>_<arch>.deb` resolves libtins
  automatically. The previous packages needed a separate
  `apt install libtins4.5` before `dpkg -i`.
- Release matrix drops Debian 12 (bookworm) — `libtins4.5` is not in the
  bookworm repos. Supported targets: Debian 13 (trixie), Ubuntu 24.04 LTS
  (noble), macOS arm64, and the static musl aarch64 tarball.

### Fixed

- Fall back to hostname when `getaddrinfo` returns a NULL `ai_canonname`
  (node label in output could otherwise be empty).
- Null-check `ifa_addr` in `localAddrOf`.

## v1.1.0 — 2026-05-12

### Changed

- **CPU baseline raised to x86-64-v3 on amd64** (Intel Haswell ≥ 2013,
  AMD Excavator ≥ 2015) and **ARMv8-A + CRC** (`-march=armv8-a+crc`) on
  aarch64. The aarch64 `+crc` opt-in is needed because GCC's default
  `armv8-a` profile keeps the CRC extension disabled even though the
  ARMv8.0-A spec mandates it. Aligns with Ubuntu's direction on
  performance-sensitive packages.
- Replaced the `ByteHash` FNV-1a flow-table hash with `CRC32Hash`, a
  hardware CRC32C implementation using `_mm_crc32_u64` (x86) /
  `__crc32cd` (ARM) over 8-byte strides. **~24% reduction in per-packet
  cost across all output modes** vs v1.0.0 on the reference bench
  (`-a hybrid` median: 565 ns/pkt → 429 ns/pkt). No memory layout change,
  no behavior change — only the hash function.
- Compile-time `#error` guards reject builds at lower `-march` or on
  unsupported architectures (anything that isn't x86_64 with SSE4.2 or
  aarch64 with CRC32).

### Added

- `test_crc32hash_sanity` unit test exercising determinism, single-bit
  avalanche, and 16-bit bucket distribution on 4096 synthetic keys.

## v1.0.0 — 2026-05-07

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
- Bundled systemd unit (`contrib/systemd/pping2.service`) with
  `ExecReload=/bin/kill -HUP $MAINPID` for log rotation, and shared
  environment file (`/etc/default/pping2`). Single-interface in v1;
  multi-interface and per-row interface attribution will land together
  in a future release.
- Bundled ClickHouse loader (`contrib/clickhouse/`) — batch-load script,
  cron entry, and `pping_flows` table schema matching `-a` output.
  Loader rotates via atomic `mv` + `systemctl reload pping2.service`.
  Two ingest paths: `clickhouse-client` (default) speaks the native TCP
  protocol; `curl` uses the HTTP interface and needs no extra packages
  on the capture host. Selected via `PPING_INGEST` in `/etc/default/pping2`.
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

- `maxFlows` default revised to `1 << 26` (67,108,864), sized for 10G IMIX TCP
  on a single pping instance against worst-case ISP/consumer-edge flow density
  (max(peak flowCnt) measured on MAWI samplepoint-F × 2× consumer-edge multiplier
  × 2× safety, rounded up to next power of 2). RAM at full cap ~6.4 GB. Hosts
  running near the cap will see `<n> flows dropped (cap)` in summary output;
  recompile to raise. ≥ 25G deployments need RSS + N pping instances or an
  XDP/AF_XDP capture path — single-instance pping is architecturally capped
  near 10G regardless of this default.
- `maxTSvals` default revised to `size_t(1) << 25` (33,554,432), down 8× from
  the previous 256M. The previous default was over-allocated (74 GB IPv6
  worst-case) due to a flawed flow-times-tickrate sub-model; the new packet-
  bound formula (target_pps × ts_capable_fraction × tsvalMaxAge × 2× safety)
  reflects the actual upper bound — `tsTbl` keys are `(flow, TSval)` with
  `try_emplace` dedup, so entries ≤ packets-in-window. RAM at full cap
  ~6.95 GB IPv4 / ~9.23 GB IPv6.
- The per-rejection `flow limit (...) reached, dropping new flow:` stderr
  line is removed; rejections are counted in `flows dropped (cap),`.
- **Default RTT measurement now uses hybrid TS+SEQ path** (`--mode hybrid`).
  Flows previously dropped as `no_TS` (Windows, stripped-TS middleboxes) now
  produce SEQ-path samples. To restore prior behavior pass `--mode ts`.
- Default `PPING_LOGFILE` moved from `/var/log/pping.log` to
  `/var/log/pping/pping.log`. The systemd install target now creates the
  parent directory owned by `nobody` (the user pping drops to after opening
  the packet socket). Without this, the post-rotation `open(O_CREAT)` on
  SIGHUP fails with EACCES under `/var/log/`'s root-only ownership and pping
  silently keeps writing to the renamed `.load` inode.

### Fixed

- **Loader rotation now actually works under privilege drop.** Pre-fix,
  `pping-load.sh` would `mv pping.log → pping.log.load` and `systemctl
  reload pping`, but pping (running as `nobody` after `dropPrivileges`)
  could not create a fresh `pping.log` in the root-owned `/var/log/`
  directory; it kept writing to the renamed `.load` inode and the loader's
  next-minute `[ -s "$LOGFILE" ]` check silently exited. Net effect: a
  single growing `pping.log.load`, no new `pping.log`, no rows reaching
  ClickHouse, and no error visible to the operator. Fixed by relocating
  the logfile to `/var/log/pping/` (see Changed entry above) so the
  reopen succeeds.
- **Loader diagnostic output now reaches syslog/journal.** `pping-load.sh`
  routes its own messages through `logger -s -t pping-load -p daemon.<level>`
  and pipes the ingest tool's stderr through the same logger. Before, a
  misconfigured `CH_ARGS` (wrong host, bad password, etc.) produced output
  only on the script's stderr — which on systems without an MTA
  configured for cron silently went nowhere, so a sysadmin running with a
  bad ClickHouse address saw no errors anywhere. The script also now logs
  a `daemon.warning` once per minute when a stale `.load` file blocks
  ingest, instead of exiting silently.

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
