# pping (pollere passive ping)

_pping_ is a linux/macOS/BSD command line tool to measure network
latency via passive monitoring of active connections.  Unlike _ping_,
pping doesn't inject traffic to determine RTT (Round-Trip Time) -- it
reports the per-packet RTT experienced by normal application traffic.
Unlike transport state monitoring tools like _ss_ which can only measure
RTT at the sending endpoint, pping can measure RTT at the sender,
receiver or anywhere on a connection's path (for example, an OpenWrt
home border router could easily monitor the RTT of all traffic to and
from the Internet).

For more information on pping, please visit http://pollere.net/pping.html

For on-going work that incorporates the pping approach within an ISP, see: https://github.com/thebracket/cpumap-pping

## Compiling ##

### Prerequisites

[pping](https://github.com/pollere/pping/) depends on
the [libtins](http://libtins.github.io/) packet parsing library
which should be [downloaded](http://libtins.github.io/download/) and
built or installed first.

pping uses only the core functions of libtins so, if there are no other
users, a static version of the library with fewer dependencies
(only _cmake_ and _libpcap_) can be built and 'installed' in its own
source directory:
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

The pping makefile assumes libtins has been built and installed in
directory `~/src/libtins` as described above. If that isn't the case,
edit the third line of the makefile to be the libtins install location.
For example, if the libtins precompiled binary is installed, change the
third line to:
```Shell
LIBTINS = /usr/local
```
Nothing else in Makefile should require changing and just typing `make`
should build pping.

There's currently no _install_ target in the makefile because pping
for live traffic (as opposed to running it on a pcap file)
requires packet sniffing capabilities and there's no standard way
to set that up (see the notes on "Reading packets from a network
interface" in `man pcap`). It can always be run as root via `sudo`.

## Examples ##

`pping -i` _interface_ `  ` monitors tcp traffic on _interface_ and reports
each packet's RTT to stdout. For example
   `pping -i en0    ` (Mac OS)
   `pping -i wlp2s0 ` (Ubuntu 17.04)

`pping -r` _pcapfile_ `  ` prints the RTT of tcp packets captured
with _tcpdump_ or _wireshark_ to _pcapfile_.

There are a few flags that control how long pping will capture and/or how
many packets it will capture, the output format, and a bpf filter for
what packets to capture. For example, to see the RTT of next 100
tcp packets from netflix or youtube:
```Shell
   pping -i en0 -c 100 -f 'net 45.57 or 74.125'
```
`pping -h`, `pping --help`, or just `pping` describes the flags.

Since pping outputs one line per packet, if it's being run on a busy
interface its output should be redirected to a file or piped to a
summarization or plotting utility. In the latter case, the `-m`
(machine-friendly output format) might be useful.

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

## Benchmarking ##

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


