# pping (improved fork)

Maintained fork of [Pollere's passive ping](https://github.com/pollere/pping)
with significant additions for performance, broader workload support, and
operational ergonomics.

_pping_ measures TCP round-trip time by passively monitoring active
connections — it doesn't inject traffic. It works on Linux, macOS, and BSD,
and (new in this fork) handles flows from clients that omit the TCP timestamp
option (Windows, middleboxes that strip it). Unlike per-endpoint tools like
`ss`, pping can measure RTT at the sender, receiver, or anywhere on a
connection's path — for example, an OpenWrt border router can monitor RTT
of all traffic to and from the Internet.

For background on the original project, see <http://pollere.net/pping.html>.
For an XDP/eBPF-based ISP-scale variant, see [thebracket/cpumap-pping](https://github.com/thebracket/cpumap-pping).

## What's changed from upstream

- **SEQ/ACK measurement path** — measures RTT on flows without the TCP timestamp
  option (Windows, stripped-TS middleboxes). Selectable via
  `--mode {ts,seq,hybrid}`; `hybrid` is the new default.
- **Packed POD `FlowKey` hot path** — replaces the original string-keyed
  hashmaps; meaningfully reduces per-packet CPU on large flow counts.
- **Extended machine-readable output** (`-e`) — adds byte counters, separate
  source/dest port columns, capture-node FQDN, and the `t`/`s` path tag.
  Designed for direct ingestion into ClickHouse or similar.
- **Privilege drop + compile hardening** — opens the packet socket as root,
  then drops to `nobody` before parsing untrusted bytes.
  `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, full RELRO, NX stack.
- **CI on every push** (GitHub Actions + GitLab CI) with a real test suite:
  unit tests, an integration pcap, format regression, and 9 SEQ/ACK golden
  files covering 3 fixtures × 3 modes.
- **Wall-clock benchmark line** in `-r` mode for throughput regression
  detection (`ns/pkt` and `Mpps`).
- Smaller fixes: SIGINT/SIGTERM flush the summary on exit, no-throw
  TSopt parse (removes a hot-path exception unwind), tuned flush cadence
  for live-capture machine-readable output.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list.

## Compiling

### Prerequisites

pping depends on the [libtins](http://libtins.github.io/) packet parsing
library, which should be [downloaded](http://libtins.github.io/download/) and
built or installed first.

pping uses only the core functions of libtins, so a static version with fewer
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

(The static libtins library makes the pping binary more self-contained
so it will run on systems that don't have libtins installed.)

## Building

The pping makefile assumes libtins has been built and installed in `~/src/libtins`
as described above. If that isn't the case, override on the command line:

```Shell
make LIBTINS=/usr/local
```

There's no `install` target — pping for live traffic needs packet sniffing
capabilities and there's no portable way to set that up. Two options:

```Shell
sudo ./pping -i eth0                          # run as root
sudo setcap cap_net_raw+ep ./pping            # grant capability once
./pping -i eth0                               #   then run as your user
```

The `setcap` form is preferred — pping drops privileges to `nobody` after
opening the socket, but starting unprivileged is simpler.

## Examples

`pping -i <interface>` monitors TCP traffic on the given interface and reports
each packet's RTT to stdout:

```Shell
pping -i en0          # macOS
pping -i wlp2s0       # Linux
```

`pping -r <pcapfile>` prints the RTT of TCP packets from a pcap captured with
`tcpdump` or Wireshark.

A few flags control capture duration, output format, and BPF filter. For
example, to see the RTT of the next 100 TCP packets to/from Netflix or YouTube:

```Shell
pping -i en0 -c 100 -f 'net 45.57 or 74.125'
```

`pping -h`, `pping --help`, or just `pping` describes all flags.

Since pping outputs one line per RTT measurement, on a busy interface its
output should be redirected to a file or piped to a summarization or plotting
utility. Two parseable formats are designed for that:

- `-m` — compact (timestamp, RTT, srcIP, dstIP)
- `-e` — extended (adds minRTT, byte counters, ports, capture-node FQDN, path tag)

## Measurement modes

pping has two RTT measurement paths and a hybrid that combines them:

- **TS path** (TCP timestamp option, RFC 7323): the original method. Works on
  Linux/BSD/macOS. Flows without timestamps (Windows, stripped-TS middleboxes)
  produce no samples.
- **SEQ path** (TCP sequence/acknowledgement numbers): works on every TCP flow.
  Tracks one outstanding `(seq + len, capture_time)` per flow direction;
  matches when the reverse ACK reaches that boundary; drops samples whose
  forward window was retransmitted (strict Karn).

Select with `--mode {ts,seq,hybrid}` (default: `hybrid`).

```Shell
./pping --mode ts     -r capture.pcap   # legacy TS-only
./pping --mode seq    -r capture.pcap   # SEQ on every flow (ignores TSopt)
./pping --mode hybrid -r capture.pcap   # TS where available, SEQ otherwise
```

`-e` extended output adds a 12th field — `t` (TS path) or `s` (SEQ path) —
appended after `node`. Human-readable output gains a trailing `[t]`/`[s]`
tag. The compact `-m` format is unchanged.

The summary line gains three new counters when non-zero:
`<n> seq samples,` `<n> seq karn drops,` `<n> seq stale,`.

The `no_TS` counter only increments in `--mode ts` (where non-TS packets are
dropped). In `seq` and `hybrid` modes those packets are handled by the SEQ
path and are not counted.

## Benchmarking

In file mode (`-r`), pping prints a wall-clock summary line to stderr at the
end of the run:

```
wall-clock: 4.213s, 1000000 packets, 4213.0 ns/pkt, 0.237 Mpps
```

`ns/pkt` and `Mpps` are the same measurement (average over the run) in
different units. This number reflects pping's CPU-bound throughput.

Live capture (`-i`) does not print this line: throughput on a live interface
is bounded by the network's actual packet rate, not by pping, so the number
would just describe how quiet the wire is.

To benchmark on a representative workload, capture from a real interface and
replay through pping in file mode:

```Shell
sudo tcpdump -i eth0 -s 144 -c 1000000 -w bench.pcap tcp
./pping -r bench.pcap > /dev/null
```

If you need to find where the time goes, profile with perf:

```Shell
perf record -F 999 -g -- ./pping -r bench.pcap > /dev/null
perf report
```

## Releases

See [`CHANGELOG.md`](CHANGELOG.md) for release notes.
