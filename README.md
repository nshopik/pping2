# pping2

_pping2_ measures TCP round-trip time by passively monitoring active
connections — it doesn't inject traffic. It works on Linux, macOS, and BSD,
and handles flows from clients that omit the TCP timestamp option (Windows,
middleboxes that strip it). Unlike per-endpoint tools like `ss`, pping2 can
measure RTT at the sender, receiver, or anywhere on a connection's path —
for example, an OpenWrt border router can monitor RTT of all traffic to and
from the Internet.

## Key features

- **Hybrid RTT measurement** — SEQ/ACK path covers flows without TCP timestamps
  (Windows, stripped-TS middleboxes); `--mode hybrid` is the default.
- **Aggregated output** (`-a`) — one row per flow per window, built for direct
  ClickHouse ingest.
- **~2× throughput over upstream** — packed POD hot path, allocation-free IP
  formatting, localtime caching.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list of changes.

## Install

### Debian / Ubuntu (recommended)

Built for Debian 13 (trixie) and Ubuntu 24.04 LTS (noble). Download the `.deb`
from the [Releases](https://github.com/nshopik/pping2/releases) page, then:

```sh
sudo apt install ./pping2_<version>_<distro>_<arch>.deb
```

`apt` pulls `libtins4.5` and `libpcap0.8t64` automatically. `postinst` sets
`cap_net_raw` on the binary and creates `/var/log/pping2/` owned by `nobody`.
Edit `/etc/default/pping2` to set your interface, then:

```sh
sudo systemctl enable --now pping2
```

### From a binary tarball

Download `pping2-<version>-macos-<arch>.tar.gz` (or, on aarch64 Linux,
`pping2-<version>-linux-aarch64-musl-static.tar.gz` for a fully static
build) from [Releases](https://github.com/nshopik/pping2/releases), extract,
then:

```sh
tar xzf pping2-<version>-macos-arm64.tar.gz
cd pping2-<version>-macos-arm64
sudo make install              # binary + setcap
sudo make install-all          # binary + systemd + ClickHouse loader (Linux)
```

### From source

See **Compiling** below.

## Compiling

### CPU baseline

The build targets **x86-64-v3** on amd64 (Intel Haswell ≥ 2013, AMD Excavator
≥ 2015 — covers all server CPUs of the last decade) and **ARMv8-A + CRC**
(`-march=armv8-a+crc`) on aarch64. The flow-table hash uses hardware CRC32C
instructions (`_mm_crc32_u64` on x86, `__crc32cd` on ARM), so SSE4.2 / ARMv8
CRC32 is required at compile time. The aarch64 `+crc` opt-in is needed because
GCC's default `armv8-a` profile keeps the CRC extension off even though the
ARMv8.0-A spec mandates it. This aligns with Ubuntu's direction on
performance-sensitive packages, which have begun targeting x86-64-v3 rather
than the default `amd64` (v1) baseline.

For CPUs older than this, edit `-march=x86-64-v3` / `-march=armv8-a+crc` out
of the Makefile and replace `CRC32Hash` with a software fallback — not
supported out of the box.

### Prerequisites

pping2 depends on the [libtins](http://libtins.github.io/) packet parsing
library, which should be [downloaded](http://libtins.github.io/download/) and
built or installed first.

pping2 uses only the core functions of libtins, so a static version with fewer
dependencies (only _cmake_ and _libpcap_) can be built and 'installed' in its
own source directory:

```Shell
# (assuming sources are put in ~/src)
cd ~/src
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build
cd build
cmake ../ -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 \
 -DLIBTINS_ENABLE_ACK_TRACKER=0 -DLIBTINS_ENABLE_WPA2=0 \
 -DCMAKE_INSTALL_PREFIX=`dirname $PWD`
make
make install
```

(The static libtins library makes the pping2 binary more self-contained
so it will run on systems that don't have libtins installed.)

## Building

The pping2 makefile assumes libtins has been built and installed in `~/src/libtins`
as described above. If that isn't the case, override on the command line:

```Shell
make LIBTINS=/usr/local
```

## Installing

The Makefile ships three install targets and an umbrella:

```Shell
sudo make install              # binary + setcap cap_net_raw+ep on Linux
sudo make install-systemd      # +pping2.service, /etc/default/pping2
sudo make install-clickhouse   # +cron loader, +schema.sql for the pping_flows table
sudo make install-all          # all three (Linux only)
```

Each has a matching `uninstall*` target. `DESTDIR` and `PREFIX` are honored
for distro packagers; `setcap` is skipped (with a warning) when `DESTDIR` is
set so packaging postinst scripts can apply it. Installed scripts have their
paths rewritten at install time, so `make install-all PREFIX=/usr` produces
a coherent install (no hardcoded `/usr/local` references in the cron, unit,
loader).

For the worked end-to-end example (pping2 → cron loader → ClickHouse), see
[`clickhouse.md`](clickhouse.md).

### Running without installing

If you'd rather not install, two ad-hoc options work:

```Shell
sudo ./pping2 -i eth0                          # run as root
sudo setcap cap_net_raw+ep ./pping2            # grant capability once
./pping2 -i eth0                               #   then run as your user
```

The `setcap` form is preferred — pping2 drops privileges to `nobody` after
opening the socket, but starting unprivileged is simpler.

## Examples

`pping2 -i <interface>` monitors TCP traffic on the given interface and reports
each packet's RTT to stdout:

```Shell
pping2 -i en0          # macOS
pping2 -i wlp2s0       # Linux
```

`pping2 -r <pcapfile>` prints the RTT of TCP packets from a pcap captured with
`tcpdump` or Wireshark.

A few flags control capture duration, output format, and BPF filter. For
example, to see the RTT of the next 100 TCP packets to/from Netflix or YouTube:

```Shell
pping2 -i en0 -c 100 -f 'net 45.57 or 74.125'
```

`pping2 -h`, `pping2 --help`, or just `pping2` describes all flags.

pping2 outputs one line per RTT measurement. On a busy interface, redirect to
a file or pipe to a summarization or plotting utility. The exact format is
selected by `-m` (compact) or `-e` (extended); see below.

## Output formats

Four formats are available. Each prints one line per RTT measurement (or
per flow window in aggregate mode).

### Field reference

| Field | Meaning |
| --- | --- |
| `epoch.usec` | Unix capture time, microsecond precision. |
| `time` | Local capture time (`%T`). |
| `RTT` | Round-trip time. Seconds (machine formats); SI-formatted with adaptive precision (default). |
| `minRTT` / `min_rtt` | Minimum RTT observed for this flow. (`min_rtt` in `-a` output.) |
| `n_samples` | Count of RTT matches in this aggregate window. |
| `fBytes` | Total bytes through the capture point on this flow direction. |
| `dBytes` | Bytes departed when this RTT's timestamp was recorded. |
| `pBytes` | Bytes since the previous RTT sample on this flow. |
| `srcIP`/`sport` | TCP source. |
| `dstIP`/`dport` | TCP destination. |
| `node` | Capture host's FQDN. |
| `tag` | `t` (TCP-timestamp path) or `s` (SEQ/ACK path). |

### Default — human-readable

```
time RTT minRTT src:sport+dst:dport [tag]
15:30:42 12.3ms 8.7ms 192.168.1.5:54321+34.107.221.82:443 [t]
```

### `-m` — machine-readable, compact

```
epoch.usec RTT srcIP dstIP
1715876442.123456 0.012300 192.168.1.5 34.107.221.82
```

### `-e` — machine-readable, extended

```
epoch.usec RTT minRTT fBytes dBytes pBytes srcIP sport dstIP dport node tag
1715876442.123456 0.012300 0.008700 1234567 1200000 1500 192.168.1.5 54321 34.107.221.82 443 host.example.com t
```

### `-a` — aggregated, one row per flow

```
epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag
1715876442.123456 0.008700 247 192.168.1.5 54321 34.107.221.82 443 host.example.com t
```

Triggers: FIN (this direction's flow), RST (both directions), idle expiry
(`--flowMaxIdle`), age-cap (`--flowMaxAge`), shutdown flush. Mutually
exclusive with `-e` and `-m`.

```Shell
./pping2 -a -r capture.pcap                     # aggregated; default age-cap = 1800s
./pping2 -a --flowMaxAge=900 -r capture.pcap    # 15-min windows for investigation
./pping2 -a --flowMaxAge=0   -r capture.pcap    # cap disabled — emit on close/idle only
```

## Measurement modes

pping2 has two RTT measurement paths and a hybrid that combines them:

- **TS path** (TCP timestamp option, RFC 7323): the original method. Works on
  Linux/BSD/macOS. Flows without timestamps (Windows, stripped-TS middleboxes)
  produce no samples.
- **SEQ path** (TCP sequence/acknowledgement numbers): works on every TCP flow.
  Tracks one outstanding `(seq + len, capture_time)` per flow direction;
  matches when the reverse ACK reaches that boundary; drops samples whose
  forward window was retransmitted (strict Karn).

Select with `--mode {ts,seq,hybrid}` (default: `hybrid`).

```Shell
./pping2 --mode ts     -r capture.pcap   # legacy TS-only
./pping2 --mode seq    -r capture.pcap   # SEQ on every flow (ignores TSopt)
./pping2 --mode hybrid -r capture.pcap   # TS where available, SEQ otherwise
```

Which path produced a sample is shown in the output (see Output formats above):
`[t]` / `[s]` in the default format, the `tag` field in `-e`. The `-m` format
omits the tag.

The summary line gains three new counters when non-zero:
`<n> seq samples,` `<n> seq karn drops,` `<n> seq stale,`.

The `no_TS` counter only increments in `--mode ts` (where non-TS packets are
dropped). In `seq` and `hybrid` modes those packets are handled by the SEQ
path and are not counted.

## Benchmarking

```Shell
./pping2 -m -r bench.pcap > /dev/null
```

prints a wall-clock summary line to stderr:

```
wall-clock: 1.787s, 4000000 packets, 446.7 ns/pkt, 2.24 Mpps
```

Live capture (`-i`) does not print this line.

### Line-rate rule of thumb

At 10 Gbit/s line rate each packet on the wire has a fixed per-packet budget
(frame + 8 B preamble + 12 B inter-frame gap, all at 10 Gb/s):

| Frame size | Per-packet budget | Line-rate pps |
| :--------- | :---------------- | :------------ |
| 64 B (minimum) | **~67 ns** | 14.88 Mpps |
| 512 B          | ~430 ns    | 2.34 Mpps  |
| 1500 B (default MTU) | ~1216 ns | 822 kpps |

### Reference numbers

Run the bench harness on your hardware (`make bench` writes a dated baseline
under `docs/superpowers/baselines/`). For reference, on an Intel i7-12700F
(Alder Lake, x86-64-v3), 4 M-packet pcap, 10 iterations median:

| mode | ns/pkt | Mpps |
| :--- | -----: | ---: |
| `-a` hybrid (aggregated) | 428.6 | 2.33 |
| `-m` hybrid (compact)    | 465.7 | 2.15 |
| human (default)          | 507.1 | 1.96 |
| `-e` hybrid (extended)   | 562.1 | 1.78 |

## Releases

See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

---

_pping2 is a fork of [Pollere's pping](https://github.com/pollere/pping)._
