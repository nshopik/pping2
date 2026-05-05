# SEQ/ACK-based RTT measurement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a TCP SEQ/ACK-based RTT measurement path so pping produces samples on flows without TCP timestamps (Windows DNS-over-TCP, stripped-TS middleboxes), selectable via `--mode {ts,seq,hybrid}` (default `hybrid`).

**Architecture:** Single-process change to `pping.cpp`. Each flow is classified once on its first packet (`tsCapable` set from TSopt presence). A new SEQ path tracks one outstanding `(seq+effective_len, capTm)` measurement per flow direction, matched by the reverse direction's ACK reaching that boundary. Strict Karn invalidates samples whose forward window was retransmitted. The existing TS-path output is factored into a shared `emit()` helper that both paths call; output gains a `t`/`s` tag (12th `-e` field, trailing `[t]`/`[s]` on human format; `-m` unchanged). No second hashmap — SEQ state lives in `flowRec` and is bounded by the existing flow eviction loop.

**Tech Stack:** C++17, libtins (TCP/IP parsing), libpcap, getopt_long. Tests: POSIX sh + the existing hand-rolled unit-test harness; new pcap fixtures synthesized with scapy.

---

## File Structure

**Modify:**
- `pping.cpp` — Mode enum, CLI flag, classification, SEQ path, `emit()` factor-out, counters, cleanup, summary, help text. The existing TS path stays in `process_packet`; new code is additive except the output block which moves into `emit()`.
- `test/unit_tests.cpp` — Add `seq_lt`/`seq_geq` and classification-bit unit tests.
- `test/test_format.sh` — Bump `-e` field count assertion 11 → 12; assert field 12 is `t` on the existing TS-only fixture.
- `test/test_integration.sh` — Same field-count and tag assertions as above.
- `test/run_tests.sh` — Wire new shell tests (`test_seq.sh`, `cross_mode_check.sh`).
- `README.md` — Document `--mode`, output schema change, new counters in the summary.
- `Makefile` — Add a `pcaps` target that regenerates the synthesized pcaps from `test/synth/`. No change to compile flags.

**Create:**
- `test/synth/__init__.py` — empty package marker.
- `test/synth/common.py` — Shared scapy helpers (deterministic ISN seeding, pcap writer wrapper, default Ethernet MACs, helper for "DNS-over-TCP" payload shape).
- `test/synth/dns_tcp_linux.py` — Synth #1: 5 flows × ~10 packets, TCP TSopt present.
- `test/synth/dns_tcp_windows.py` — Synth #2: same 5-flow shape, Windows TCP options (MSS + SACK-Permitted + WScale, **no** TSopt).
- `test/synth/mixed_with_retx.py` — Synth #3: 3 flows, one with a retransmission while a measurement is in flight; 2 controls.
- `test/synth/build.py` — Driver: imports the three modules and writes their pcaps to `test/pcaps/`.
- `test/pcaps/dns-tcp-linux.pcap`, `test/pcaps/dns-tcp-windows.pcap`, `test/pcaps/mixed-with-retx.pcap` — checked-in synthesized output.
- `test/golden/dns-tcp-linux.{ts,seq,hybrid}.golden` — 3 files.
- `test/golden/dns-tcp-windows.{ts,seq,hybrid}.golden` — 3 files.
- `test/golden/mixed-with-retx.{ts,seq,hybrid}.golden` — 3 files.
- `test/test_seq.sh` — Runs `pping -e -r <pcap> --mode <m>` for all 9 (pcap, mode) pairs and diffs against goldens.
- `test/cross_mode_check.sh` — Asserts `-e` output of `dns-tcp-linux.pcap` is bit-identical between `--mode ts` and `--mode hybrid` (modulo the 12th tag column, which must be `t` in both).
- `test/bench.sh` — Runs each pcap × each mode, prints `ns/pkt` and `Mpps` from pping's wall-clock summary. No CI gate.
- `CHANGELOG.md` — New file (project has none today). Record the default-mode change and the 12th `-e` field.

Each task below either modifies one of the files above end-to-end or adds one new file end-to-end, so each task lands as a single self-contained commit.

---

## Task 1: Wrap-safe sequence comparison helpers

**Files:**
- Modify: `pping.cpp` (add helpers near top of the file, before `flowRec`)
- Modify: `test/unit_tests.cpp` (new test cases)

- [ ] **Step 1: Write the failing test**

In `test/unit_tests.cpp`, add after `test_flowkey_v4_v6_disambig` (around line 227):

```cpp
static void test_seq_compare_wrap()
{
    // Identity / adjacent
    ASSERT_EQ(seq_lt(1u, 2u), true);
    ASSERT_EQ(seq_lt(2u, 1u), false);
    ASSERT_EQ(seq_lt(5u, 5u), false);
    ASSERT_EQ(seq_geq(5u, 5u), true);
    ASSERT_EQ(seq_geq(6u, 5u), true);
    ASSERT_EQ(seq_geq(4u, 5u), false);

    // Wrap: a just below 2^32, b just above 0. a < b in stream order.
    const uint32_t near_max = 0xFFFFFFFEu;
    const uint32_t small    = 0x00000002u;
    ASSERT_EQ(seq_lt(near_max, small), true);
    ASSERT_EQ(seq_geq(small, near_max), true);

    // Half-window boundary: 2^31 apart is undefined per RFC; document
    // that we treat (a, a + 2^31) as "a < a + 2^31" (positive int32 diff).
    const uint32_t a = 0x10000000u;
    const uint32_t b = a + 0x80000000u; // exactly 2^31 ahead
    ASSERT_EQ(seq_lt(a, b), false);   // int32(a-b) = INT32_MIN, which is < 0
                                       // but the convention we want here is "not less than"
                                       // — see implementation note below.
}
REGISTER_TEST(test_seq_compare_wrap);
```

Note: the third block documents the half-window edge case. If `seq_lt(a, b)` for exactly-2^31 distance must return `true` to match the implementation, flip the assertion. The spec defines the comparison as `int32_t(a - b) < 0`, and `INT32_MIN < 0` is true, so the assertion will become `ASSERT_EQ(seq_lt(a, b), true);`. Use whichever the implementation in Step 3 produces; the goal is to lock current behavior in.

- [ ] **Step 2: Build and run tests to verify the new test fails**

Run: `make check`
Expected: build fails with "undeclared identifier `seq_lt`/`seq_geq`".

- [ ] **Step 3: Add the helpers to pping.cpp**

Insert after the `ByteHash` struct definition (currently around line 138, before `class flowRec`):

```cpp
// Wrap-safe TCP sequence-number comparison. Treats a, b as points on a
// 2^32 cycle; correct as long as |a - b| < 2^31 (RFC 1323 PAWS bound).
// Used unconditionally on the SEQ-path hot path; cost is sub/sign-compare.
static inline bool seq_lt(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) < 0;
}
static inline bool seq_geq(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) >= 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make check`
Expected: `unit_tests` passes; `test_seq_compare_wrap` listed in PASS output. If the half-window assertion in Step 1 was inverted, fix it now.

- [ ] **Step 5: Commit**

```bash
git add pping.cpp test/unit_tests.cpp
git commit -m "Add wrap-safe seq_lt/seq_geq helpers for SEQ-path use"
```

---

## Task 2: Add Mode enum and `--mode` CLI flag

**Files:**
- Modify: `pping.cpp` (enum near top, parse in main, no behavioral wiring yet)

- [ ] **Step 1: Add the Mode enum and global**

After the `tsDropped` declaration (around line 200), add:

```cpp
enum class Mode { TS, SEQ, HYBRID };
static Mode mode = Mode::HYBRID;
```

- [ ] **Step 2: Add `--mode` to the long-option table**

Edit the `opts[]` array (around line 588) to add the long option just before the `{0,0,0,0}` terminator:

```cpp
    { "mode",      required_argument, nullptr,  0  },   // long-only
```

(Use sentinel `flag=0` so getopt returns 0 and we dispatch on `optarg`. Index of this entry in the array is needed in the parser below.)

- [ ] **Step 3: Parse `--mode` in `main()`**

In the `for (int c; (c = getopt_long(...))` switch (around line 668), add a `case 0:` arm that handles the long-only `--mode`. Use `getopt_long`'s `longindex` parameter to identify which long option fired:

```cpp
    int longindex = -1;
    for (int c; (c = getopt_long(argc, argv, "i:r:f:c:s:hlmqve",
                                 opts, &longindex)) != -1; ) {
        switch (c) {
        // ... existing cases unchanged ...
        case 0: {
            // long-only options dispatched by name
            const char* name = opts[longindex].name;
            if (std::strcmp(name, "mode") == 0) {
                if      (std::strcmp(optarg, "ts")     == 0) mode = Mode::TS;
                else if (std::strcmp(optarg, "seq")    == 0) mode = Mode::SEQ;
                else if (std::strcmp(optarg, "hybrid") == 0) mode = Mode::HYBRID;
                else {
                    std::cerr << "unknown --mode value: " << optarg
                              << " (expected ts, seq, or hybrid)\n";
                    exit(EXIT_FAILURE);
                }
            }
            break;
        }
        }
    }
```

- [ ] **Step 4: Build, run with each value, and confirm parser accepts/rejects**

Run:
```bash
make
./pping --mode ts -r test/known.pcap > /dev/null && echo "ts ok"
./pping --mode seq -r test/known.pcap > /dev/null && echo "seq ok"
./pping --mode hybrid -r test/known.pcap > /dev/null && echo "hybrid ok"
./pping --mode bogus -r test/known.pcap 2>&1 | grep "unknown --mode" && echo "rejection ok"
```
Expected: 4 "ok" lines. Behavior is unchanged from baseline (no logic wired yet) — output should still match `test/known.pcap.golden` for `-m`. **Don't run `make check` yet** — Task 8 will repair the format tests for the 12th-field change; Task 2 alone leaves them passing because `-m` is unaffected and Task 8 hasn't yet introduced the `-e` change.

- [ ] **Step 5: Commit**

```bash
git add pping.cpp
git commit -m "Add Mode enum and --mode {ts,seq,hybrid} CLI flag (default hybrid)"
```

---

## Task 3: Extend `flowRec` with SEQ-path fields and classification bit

**Files:**
- Modify: `pping.cpp` (class `flowRec` around line 140)

- [ ] **Step 1: Add the new fields**

Replace the body of `class flowRec` (lines 140–158) with:

```cpp
class flowRec
{
  public:
    flowRec() = default;
    ~flowRec() = default;

    double last_tm{};
    double min{1e30};
    double bytesSnt{};
    double lstBytesSnt{};
    double bytesDep{};
    bool   revFlow{};

    // SEQ-path state (used in --mode seq and --mode hybrid for non-TS flows)
    uint32_t outstanding_end{0};   // expected ack; 0 = no measurement in flight
    double   outstanding_time{0.}; // capTm at store
    uint32_t high_seq{0};          // highest seq+eff_len seen forward
    bool     high_seq_init{false}; // sentinel-safe across full uint32 range
    bool     retx_flag{false};     // strict Karn: invalidate sample if set

    // Set once on first packet through process_packet, then never modified.
    bool     tsCapable{false};
    bool     classified{false};
};
```

- [ ] **Step 2: Build to confirm no regressions**

Run: `make`
Expected: clean build. No behavioral change yet.

- [ ] **Step 3: Add a unit test for default-init zeroing**

In `test/unit_tests.cpp`, after `test_seq_compare_wrap`:

```cpp
static void test_flowrec_seq_field_defaults()
{
    flowRec fr;
    ASSERT_EQ((int)fr.outstanding_end, 0);
    ASSERT_EQ(fr.outstanding_time, 0.0);
    ASSERT_EQ((int)fr.high_seq, 0);
    ASSERT_EQ(fr.high_seq_init, false);
    ASSERT_EQ(fr.retx_flag, false);
    ASSERT_EQ(fr.tsCapable, false);
    ASSERT_EQ(fr.classified, false);
}
REGISTER_TEST(test_flowrec_seq_field_defaults);
```

- [ ] **Step 4: Run tests**

Run: `make check`
Expected: new test passes; integration/format tests still pass (no output change yet).

- [ ] **Step 5: Commit**

```bash
git add pping.cpp test/unit_tests.cpp
git commit -m "Extend flowRec with SEQ-path fields and classification bit"
```

---

## Task 4: Add SEQ counters and surface them in `printSummary`

**Files:**
- Modify: `pping.cpp` (counters near `tsDropped` declaration, summary print, summary reset in `main`)

- [ ] **Step 1: Add the three counters**

After `static int tsDropped;` (around line 200), add:

```cpp
static int seqSamples;     // production: RTT samples emitted via SEQ path
static int seqKarnDrops;   // diagnostic: samples discarded by strict Karn
static int seqStale;       // diagnostic: outstanding measurements aged out
```

- [ ] **Step 2: Print them in `printSummary` via `printnz`**

Edit `printSummary` (around line 576) to add three lines inside the chained string concat:

```cpp
static void printSummary()
{
    std::cerr << flowCnt << " flows, "
              << pktCnt << " packets, " +
                 printnz(no_TS, " no TS opt, ") +
                 printnz(uniDir, " uni-directional, ") +
                 printnz(not_tcp, " not TCP, ") +
                 printnz(not_v4or6, " not v4 or v6, ") +
                 printnz(tsDropped, " tsTbl drops, ") +
                 printnz(seqSamples, " seq samples, ") +
                 printnz(seqKarnDrops, " seq karn drops, ") +
                 printnz(seqStale, " seq stale, ") +
                 "\n";
}
```

- [ ] **Step 3: Reset them in the periodic-summary block in `main`**

Edit the `if (capTm >= nxtSum && sumInt)` block (around line 778) so the per-interval reset clears the three new counters too:

```cpp
        if (capTm >= nxtSum && sumInt) {
            if (nxtSum > 0.) {
                printSummary();
                pktCnt = 0;
                no_TS = 0;
                uniDir = 0;
                not_tcp = 0;
                not_v4or6 = 0;
                tsDropped = 0;
                seqSamples = 0;
                seqKarnDrops = 0;
                seqStale = 0;
            }
            nxtSum = capTm + sumInt;
        }
```

- [ ] **Step 4: Build and confirm summary output is unchanged for current pcap**

Run: `make && ./pping -v -r test/known.pcap 2>&1 >/dev/null | grep flows`
Expected: same shape as before — no SEQ counter shows because all three are 0 (printnz suppresses zeros). `1 flows, 6 packets, 1 uni-directional,` (or similar; the exact string depends on what already prints).

- [ ] **Step 5: Commit**

```bash
git add pping.cpp
git commit -m "Add seq_samples / seq_karn_drops / seq_stale counters to summary"
```

---

## Task 5: Synthesize `dns-tcp-linux.pcap`

This and the next two tasks set up test fixtures before any SEQ logic, so the SEQ-path tasks have something to assert against. Each pcap commits separately so review can sanity-check the binary fixture before code uses it.

**Files:**
- Create: `test/synth/__init__.py`
- Create: `test/synth/common.py`
- Create: `test/synth/dns_tcp_linux.py`
- Create: `test/synth/build.py`
- Create: `test/pcaps/dns-tcp-linux.pcap`

- [ ] **Step 1: Document the scapy dependency**

scapy is a dev-only dep (test-fixture regeneration). Pcaps are checked in, so contributors don't need scapy unless they want to regen.

Create `test/synth/__init__.py` (empty):

```bash
mkdir -p test/synth test/pcaps
touch test/synth/__init__.py
```

- [ ] **Step 2: Write `test/synth/common.py`**

```python
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
```

- [ ] **Step 3: Write `test/synth/dns_tcp_linux.py`**

```python
"""
dns-tcp-linux.pcap — 5 DNS-over-TCP flows (Linux client → resolver), TSopt present.
Each flow: SYN, SYN-ACK, ACK, query (PSH-ACK), server ACK, response (PSH-ACK),
client ACK, FIN, FIN-ACK, ACK. ~10 packets * 5 flows = 50 packets.
Each packet is RTT_SEC apart so RTT samples are 0.050000 in golden output.
"""
import time
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260505)
    pkts = []
    base_ts = 1_000_000_000  # epoch seconds for first packet
    base_tsval_c = 100_000   # client TSval starts here, +1 per pkt
    base_tsval_s = 200_000   # server TSval

    for i in range(5):
        cip = f"10.0.0.{10 + i}"
        sip = "10.0.1.1"
        cport = 40000 + i
        sport = 53
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0  # space flows 1s apart

        def C2S(seq, ack, flags, payload, t_off, opts):
            return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
                   IP(src=cip, dst=sip) / \
                   TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        def S2C(seq, ack, flags, payload, t_off, opts):
            return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
                   IP(src=sip, dst=cip) / \
                   TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        # Client TSval increments per packet sent
        cts = base_tsval_c + i * 100
        sts = base_tsval_s + i * 100

        # Packets at +0, +RTT, +2RTT, ... (so query→response RTT = RTT_SEC)
        seq_steps = []
        # 0: SYN C→S
        seq_steps.append((C2S(cisn, 0, "S", b"", 0,
                              common.LIN_OPTS_SYN(cts)), 0))
        # 1: SYN-ACK S→C
        seq_steps.append((S2C(sisn, cisn + 1, "SA", b"", 1,
                              [("MSS", 1460), ("SAckOK", b""),
                               ("Timestamp", (sts, cts)),
                               ("NOP", None), ("WScale", 7)]), 1))
        # 2: ACK C→S
        seq_steps.append((C2S(cisn + 1, sisn + 1, "A", b"", 2,
                              common.LIN_OPTS_DATA(cts + 1, sts)), 2))
        # 3: query PSH-ACK C→S, 60 bytes
        query = b"\x00\x3a" + b"\x00" * 56
        seq_steps.append((C2S(cisn + 1, sisn + 1, "PA", query, 3,
                              common.LIN_OPTS_DATA(cts + 2, sts)), 3))
        # 4: server ACK S→C
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "A", b"", 4,
                              common.LIN_OPTS_DATA(sts + 1, cts + 2)), 4))
        # 5: response PSH-ACK S→C, 80 bytes
        resp = b"\x00\x4e" + b"\x00" * 76
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "PA", resp, 5,
                              common.LIN_OPTS_DATA(sts + 2, cts + 2)), 5))
        # 6: client ACK C→S
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "A", b"", 6,
                              common.LIN_OPTS_DATA(cts + 3, sts + 2)), 6))
        # 7: FIN-ACK C→S
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "FA", b"", 7,
                              common.LIN_OPTS_DATA(cts + 4, sts + 2)), 7))
        # 8: FIN-ACK S→C
        seq_steps.append((S2C(sisn + 1 + len(resp), cisn + 2 + len(query),
                              "FA", b"", 8,
                              common.LIN_OPTS_DATA(sts + 3, cts + 4)), 8))
        # 9: ACK C→S
        seq_steps.append((C2S(cisn + 2 + len(query), sisn + 2 + len(resp),
                              "A", b"", 9,
                              common.LIN_OPTS_DATA(cts + 5, sts + 3)), 9))

        for pkt, step in seq_steps:
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts


if __name__ == "__main__":
    common.write("dns-tcp-linux.pcap", build())
```

- [ ] **Step 4: Write `test/synth/build.py`**

```python
"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import common, dns_tcp_linux


def main():
    common.write("dns-tcp-linux.pcap", dns_tcp_linux.build())
    # dns_tcp_windows and mixed_with_retx added in Tasks 6 and 7.


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Generate the pcap and check it**

```bash
cd test/synth && python3 -m pip install --user scapy 2>&1 | tail -2
cd .. && python3 -m synth.build
ls -la pcaps/
```
Expected: `pcaps/dns-tcp-linux.pcap` exists, ~3-5 KB. `tcpdump -r test/pcaps/dns-tcp-linux.pcap | head -5` shows TCP packets between 10.0.0.x and 10.0.1.1.

- [ ] **Step 6: Commit**

```bash
git add test/synth/__init__.py test/synth/common.py test/synth/dns_tcp_linux.py test/synth/build.py test/pcaps/dns-tcp-linux.pcap
git commit -m "Add dns-tcp-linux.pcap fixture (5 flows, TSopt present)"
```

---

## Task 6: Synthesize `dns-tcp-windows.pcap`

**Files:**
- Create: `test/synth/dns_tcp_windows.py`
- Modify: `test/synth/build.py`
- Create: `test/pcaps/dns-tcp-windows.pcap`

- [ ] **Step 1: Write `test/synth/dns_tcp_windows.py`**

```python
"""
dns-tcp-windows.pcap — 5 DNS-over-TCP flows (Windows client), no TSopt.
Same packet shape and timing as dns-tcp-linux but TCP options are MSS +
WScale + SACK-Permitted (no Timestamp). Validates the SEQ path's headline
use case: hybrid mode produces samples, ts mode drops them as no_TS.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_500

    for i in range(5):
        cip = f"10.0.2.{10 + i}"
        sip = "10.0.3.1"
        cport = 50000 + i
        sport = 53
        cisn = common.isn()
        sisn = common.isn()

        t = float(base_ts) + i * 1.0

        def C2S(seq, ack, flags, payload, opts):
            return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
                   IP(src=cip, dst=sip) / \
                   TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        def S2C(seq, ack, flags, payload, opts):
            return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
                   IP(src=sip, dst=cip) / \
                   TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                       flags=flags, options=opts) / \
                   (Raw(load=payload) if payload else b"")

        seq_steps = []
        seq_steps.append((C2S(cisn, 0, "S", b"", common.WIN_OPTS_SYN), 0))
        seq_steps.append((S2C(sisn, cisn + 1, "SA", b"", common.WIN_OPTS_SYN), 1))
        seq_steps.append((C2S(cisn + 1, sisn + 1, "A", b"", []), 2))
        query = b"\x00\x3a" + b"\x00" * 56
        seq_steps.append((C2S(cisn + 1, sisn + 1, "PA", query, []), 3))
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "A", b"", []), 4))
        resp = b"\x00\x4e" + b"\x00" * 76
        seq_steps.append((S2C(sisn + 1, cisn + 1 + len(query), "PA", resp, []), 5))
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "A", b"", []), 6))
        seq_steps.append((C2S(cisn + 1 + len(query), sisn + 1 + len(resp),
                              "FA", b"", []), 7))
        seq_steps.append((S2C(sisn + 1 + len(resp), cisn + 2 + len(query),
                              "FA", b"", []), 8))
        seq_steps.append((C2S(cisn + 2 + len(query), sisn + 2 + len(resp),
                              "A", b"", []), 9))

        for pkt, step in seq_steps:
            pkt.time = t + step * common.RTT_SEC
            pkts.append(pkt)

    return pkts


if __name__ == "__main__":
    common.write("dns-tcp-windows.pcap", build())
```

- [ ] **Step 2: Wire into `build.py`**

```python
"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import common, dns_tcp_linux, dns_tcp_windows


def main():
    common.write("dns-tcp-linux.pcap",   dns_tcp_linux.build())
    common.write("dns-tcp-windows.pcap", dns_tcp_windows.build())


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Regenerate and inspect**

```bash
cd test && python3 -m synth.build
tcpdump -r pcaps/dns-tcp-windows.pcap -v 2>&1 | head -20
```
Expected: pcap exists; tcpdump shows TCP packets with MSS / SACK-Permitted / WScale options but no Timestamp.

- [ ] **Step 4: Commit**

```bash
git add test/synth/dns_tcp_windows.py test/synth/build.py test/pcaps/dns-tcp-windows.pcap
git commit -m "Add dns-tcp-windows.pcap fixture (5 flows, no TSopt)"
```

---

## Task 7: Synthesize `mixed-with-retx.pcap`

**Files:**
- Create: `test/synth/mixed_with_retx.py`
- Modify: `test/synth/build.py`
- Create: `test/pcaps/mixed-with-retx.pcap`

- [ ] **Step 1: Write `test/synth/mixed_with_retx.py`**

3 flows. Flow A includes a retx of a previously-sent forward segment while a measurement is in flight: that sample must be dropped by strict Karn. Flow B and C are clean controls (one TS, one no-TS) so the same pcap exercises all three modes meaningfully.

```python
"""
mixed-with-retx.pcap — 3 flows.
  A: TCP retransmission while a SEQ-path measurement is outstanding.
     SEQ path must drop that sample (seq_karn_drops++) and keep its minRTT
     untainted by the spurious "RTT" the retx would otherwise produce.
  B: clean TS-capable flow (control for ts/hybrid).
  C: clean no-TS flow (control for seq/hybrid).
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260507)
    pkts = []
    base_ts = 1_000_000_900

    # ----- Flow A: retx during measurement (no TSopt) -----
    cip, sip = "10.0.4.10", "10.0.5.1"
    cport, sport = 60000, 53
    cisn = common.isn()
    sisn = common.isn()
    t0 = float(base_ts)

    def E_C2S(seq, ack, flags, payload, opts=None):
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    def E_S2C(seq, ack, flags, payload, opts=None):
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    # 3-way handshake
    pkts.append(E_C2S(cisn,        0,           "S",  b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0
    pkts.append(E_S2C(sisn,        cisn + 1,    "SA", b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0 + 0.050
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "A",  b""));                          pkts[-1].time = t0 + 0.100
    # First data segment C→S, 100 bytes — opens the outstanding measurement
    seg1 = b"X" * 100
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "PA", seg1));                         pkts[-1].time = t0 + 0.150
    # Spurious retransmission of the SAME bytes BEFORE the ACK arrives. This
    # must trip retx_flag.
    pkts.append(E_C2S(cisn + 1,    sisn + 1,    "PA", seg1));                         pkts[-1].time = t0 + 0.180
    # Server ACK arrives — under strict Karn this match is discarded.
    pkts.append(E_S2C(sisn + 1,    cisn + 1 + 100, "A",  b""));                       pkts[-1].time = t0 + 0.200
    # Followup clean exchange (after retx_flag clears on next outstanding).
    seg2 = b"Y" * 100
    pkts.append(E_C2S(cisn + 101,  sisn + 1,    "PA", seg2));                         pkts[-1].time = t0 + 0.300
    pkts.append(E_S2C(sisn + 1,    cisn + 201,  "A",  b""));                          pkts[-1].time = t0 + 0.350
    # Teardown
    pkts.append(E_C2S(cisn + 201,  sisn + 1,    "FA", b""));                          pkts[-1].time = t0 + 0.400
    pkts.append(E_S2C(sisn + 1,    cisn + 202,  "FA", b""));                          pkts[-1].time = t0 + 0.450
    pkts.append(E_C2S(cisn + 202,  sisn + 2,    "A",  b""));                          pkts[-1].time = t0 + 0.500

    # ----- Flow B: clean TS-capable -----
    cip, sip = "10.0.4.20", "10.0.5.1"
    cport, sport = 60001, 53
    cisn = common.isn(); sisn = common.isn()
    t0 = float(base_ts) + 1.0
    cts, sts = 333_000, 444_000

    def L_C2S(seq, ack, flags, payload, tsval, tsecr):
        opts = [("NOP", None), ("NOP", None), ("Timestamp", (tsval, tsecr))]
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts) / \
               (Raw(load=payload) if payload else b"")

    def L_S2C(seq, ack, flags, payload, tsval, tsecr):
        opts = [("NOP", None), ("NOP", None), ("Timestamp", (tsval, tsecr))]
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts) / \
               (Raw(load=payload) if payload else b"")

    # SYN with TSopt
    syn_opts = common.LIN_OPTS_SYN(cts)
    pkts.append(Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) /
                IP(src=cip, dst=sip) /
                TCP(sport=cport, dport=sport, seq=cisn, ack=0, flags="S", options=syn_opts));    pkts[-1].time = t0
    synack_opts = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (sts, cts)),
                   ("NOP", None), ("WScale", 7)]
    pkts.append(Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) /
                IP(src=sip, dst=cip) /
                TCP(sport=sport, dport=cport, seq=sisn, ack=cisn+1, flags="SA", options=synack_opts)); pkts[-1].time = t0 + 0.050
    pkts.append(L_C2S(cisn+1, sisn+1, "A",  b"",       cts+1, sts));   pkts[-1].time = t0 + 0.100
    pkts.append(L_C2S(cisn+1, sisn+1, "PA", b"Q"*60,  cts+2, sts));    pkts[-1].time = t0 + 0.150
    pkts.append(L_S2C(sisn+1, cisn+61, "PA", b"R"*80,  sts+1, cts+2)); pkts[-1].time = t0 + 0.200
    pkts.append(L_C2S(cisn+61, sisn+81, "FA", b"",     cts+3, sts+1)); pkts[-1].time = t0 + 0.250
    pkts.append(L_S2C(sisn+81, cisn+62, "FA", b"",     sts+2, cts+3)); pkts[-1].time = t0 + 0.300
    pkts.append(L_C2S(cisn+62, sisn+82, "A",  b"",     cts+4, sts+2)); pkts[-1].time = t0 + 0.350

    # ----- Flow C: clean no-TS -----
    cip, sip = "10.0.4.30", "10.0.5.1"
    cport, sport = 60002, 53
    cisn = common.isn(); sisn = common.isn()
    t0 = float(base_ts) + 2.0

    def W_C2S(seq, ack, flags, payload, opts=None):
        return Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
               IP(src=cip, dst=sip) / \
               TCP(sport=cport, dport=sport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    def W_S2C(seq, ack, flags, payload, opts=None):
        return Ether(src=common.SERVER_MAC, dst=common.CLIENT_MAC) / \
               IP(src=sip, dst=cip) / \
               TCP(sport=sport, dport=cport, seq=seq, ack=ack,
                   flags=flags, options=opts or []) / \
               (Raw(load=payload) if payload else b"")

    pkts.append(W_C2S(cisn,     0,         "S",  b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0
    pkts.append(W_S2C(sisn,     cisn + 1,  "SA", b"", common.WIN_OPTS_SYN));     pkts[-1].time = t0 + 0.050
    pkts.append(W_C2S(cisn + 1, sisn + 1,  "A",  b""));                          pkts[-1].time = t0 + 0.100
    pkts.append(W_C2S(cisn + 1, sisn + 1,  "PA", b"Q"*60));                      pkts[-1].time = t0 + 0.150
    pkts.append(W_S2C(sisn + 1, cisn + 61, "PA", b"R"*80));                      pkts[-1].time = t0 + 0.200
    pkts.append(W_C2S(cisn + 61, sisn + 81, "FA", b""));                         pkts[-1].time = t0 + 0.250
    pkts.append(W_S2C(sisn + 81, cisn + 62, "FA", b""));                         pkts[-1].time = t0 + 0.300
    pkts.append(W_C2S(cisn + 62, sisn + 82, "A",  b""));                         pkts[-1].time = t0 + 0.350

    return pkts


if __name__ == "__main__":
    common.write("mixed-with-retx.pcap", build())
```

- [ ] **Step 2: Wire into `build.py`**

```python
"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import common, dns_tcp_linux, dns_tcp_windows, mixed_with_retx


def main():
    common.write("dns-tcp-linux.pcap",   dns_tcp_linux.build())
    common.write("dns-tcp-windows.pcap", dns_tcp_windows.build())
    common.write("mixed-with-retx.pcap", mixed_with_retx.build())


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Regenerate and inspect**

```bash
cd test && python3 -m synth.build
tcpdump -r pcaps/mixed-with-retx.pcap | wc -l
tcpdump -r pcaps/mixed-with-retx.pcap | grep '10.0.4.10' | wc -l
```
Expected: ~27 total packets; ~12 lines for flow A (the one with retx).

- [ ] **Step 4: Commit**

```bash
git add test/synth/mixed_with_retx.py test/synth/build.py test/pcaps/mixed-with-retx.pcap
git commit -m "Add mixed-with-retx.pcap fixture (3 flows including TCP retx)"
```

---

## Task 8: Factor TS-path output into `emit()` and add `t`/`s` tag

This is the only refactor of existing code. The new helper takes the tag char so the SEQ path can reuse it. This task changes the `-e` output schema (12th field) and human format (trailing tag), so the existing format/integration tests must be updated in lock step.

**Files:**
- Modify: `pping.cpp`
- Modify: `test/test_format.sh`
- Modify: `test/test_integration.sh`
- Modify: `test/known.pcap.golden` — unchanged (only `-m` is captured here, and `-m` is unchanged byte-for-byte). Verify in Step 6.

- [ ] **Step 1: Add the `emit()` helper**

Insert before `process_packet` (around line 282). It accepts the existing computed values and the new tag:

```cpp
// Shared output helper for both the TS and SEQ paths. `tag` is 't' (TS path)
// or 's' (SEQ path); always emitted for -e and human formats, omitted from -m.
static void emit(double rtt, flowRec* fr, const FlowKey& fk,
                 double fBytes, double dBytes, double pBytes, char tag)
{
    std::string ipsstr = ipToString(fk.srcIP, fk.af);
    std::string ipdstr = ipToString(fk.dstIP, fk.af);

    if (extendedMachineOutput) {
        printf("%" PRId64 ".%06d %.6f %.6f %.0f %.0f %.0f %s %u %s %u %s %c\n",
                int64_t(capTm + offTm), int((capTm - floor(capTm)) * 1e6),
                rtt, fr->min, fBytes, dBytes, pBytes,
                ipsstr.c_str(), fk.sport,
                ipdstr.c_str(), fk.dport,
                node.c_str(),
                tag);
    } else if (machineReadable) {
        printf("%" PRId64 ".%06d %.6f %s %s\n",
                int64_t(capTm + offTm), int((capTm - floor(capTm)) * 1e6),
                rtt, ipsstr.c_str(), ipdstr.c_str());
    } else {
        std::time_t result = static_cast<std::time_t>(int64_t(capTm + offTm));
        char tbuff[80];
        struct tm* ptm = std::localtime(&result);
        strftime(tbuff, 80, "%T", ptm);
        printf("%s %s %s %s:%u+%s:%u [%c]\n",
               tbuff, fmtTimeDiff(rtt).c_str(),
               fmtTimeDiff(fr->min).c_str(),
               ipsstr.c_str(), fk.sport, ipdstr.c_str(), fk.dport,
               tag);
    }
    int64_t now = clock_now();
    if (now - nextFlush >= 0) {
        nextFlush = now + flushInt;
        fflush(stdout);
    }
}
```

(Note: human format used to compute `result` from `pkt.timestamp().seconds()` directly. The helper recomputes it from `capTm + offTm` instead so the helper doesn't need a `Packet&` parameter. The two are equal by construction in `process_packet`.)

- [ ] **Step 2: Replace the inline output block in `process_packet` with a call to `emit()`**

In `process_packet`, replace the block from `// Defer string construction to here — only on RTT match.` through the `eit->second.t = -t;` line (currently lines 438–474) with:

```cpp
        std::string ipsstr; // not used here; emit() does its own formatting
        (void)ipsstr;       // keep removal local to this hunk

        emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');

        eit->second.t = -t;     //leaves an entry in the TS table to avoid saving
                                // this TSval again; negative marks it consumed
```

Then delete the now-unused leading `ipsstr`/`ipdstr` declarations and the old format dispatch. The final shape of the `if (eit != tsTbl.end() && eit->second.t > 0.0)` block becomes (read-only):

```cpp
    if (eit != tsTbl.end() && eit->second.t > 0.0) {
        double t = eit->second.t;
        double rtt = capTm - t;
        if (fr->min > rtt) {
            fr->min = rtt;
        }
        double fBytes = eit->second.fBytes;
        double dBytes = eit->second.dBytes;
        double pBytes = arr_fwd - fr->lstBytesSnt;
        fr->lstBytesSnt = arr_fwd;
        auto rit = flows.find(rk);
        if (rit != flows.end()) {
            rit->second->bytesDep = fBytes;
        }

        emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');

        eit->second.t = -t;
    }
```

- [ ] **Step 3: Build and check the binary still works**

Run:
```bash
make
./pping -m -r test/known.pcap > /tmp/m_after.txt
diff -u test/known.pcap.golden /tmp/m_after.txt
```
Expected: zero diff (-m unchanged).

```bash
./pping -e -r test/known.pcap | head -1
```
Expected: line ends with hostname then a single ` t` field — 12 whitespace-separated columns.

- [ ] **Step 4: Update the format-test field count and add tag check**

In `test/test_format.sh`, change every `NF != 11` to `NF != 12` (find both occurrences) and update the test name from `e_field_count` accordingly. Then add a new check after the existing field-count block:

```sh
# ---------------------------------------------------------------------------
# X. e_tag_field — field 12 is 't' (TS path) on every line for known.pcap
# ---------------------------------------------------------------------------
BAD_TAG=$(awk '$12 != "t" { print NR": "$12 }' "$TMP_E")
if [ -z "$BAD_TAG" ]; then
    pass "e_tag_field"
else
    fail "e_tag_field" "lines with wrong tag: $BAD_TAG"
fi
```

In `test/test_integration.sh`, do the same: change `NF != 11` → `NF != 12`, rename `e_field_count_11` → `e_field_count_12`, and add the same `e_tag_field` block.

- [ ] **Step 5: Run the full test suite**

Run: `make check`
Expected: all PASS, including the new `e_tag_field` checks.

- [ ] **Step 6: Confirm `-m` golden is unchanged byte-for-byte**

```bash
./pping -m -r test/known.pcap | diff -u test/known.pcap.golden -
```
Expected: empty output (zero diff).

- [ ] **Step 7: Commit**

```bash
git add pping.cpp test/test_format.sh test/test_integration.sh
git commit -m "Factor TS-path output into emit(); add t/s tag (12th -e field)"
```

---

## Task 9: Classify each flow on its first packet

**Files:**
- Modify: `pping.cpp`
- Modify: `test/unit_tests.cpp` (add classification test if practical; otherwise integration test in Task 14 covers it)

The classification bit is set early in `process_packet` so both the existing TS path and the upcoming SEQ path can read it. This task wires the bit; it does not yet change behavior.

- [ ] **Step 1: Set `tsCapable`/`classified` after the flow-record lookup, before any path-specific code**

In `process_packet`, immediately after the `fr->last_tm = capTm;` line (currently line 395), add:

```cpp
    if (!fr->classified) {
        fr->tsCapable = (tsopt != nullptr);
        fr->classified = true;
    }
```

Hoist the early-return for missing TSopt **below** the classification (so non-TS flows still get classified before being dropped). To do that, the existing `if (!tsopt || ...) { no_TS++; return; }` block (currently lines 310–313) needs to move further down — but that's the work of Task 10. For Task 9, leave the early return in place; classification simply never fires for no-TS packets yet, which is fine because Task 10 reorders.

- [ ] **Step 2: Verify the classification flag works on the existing TS pcap**

Run: `make && ./pping -e -r test/known.pcap`
Expected: 4 lines, all with `t` tag (no behavior change).

- [ ] **Step 3: Commit**

```bash
git add pping.cpp
git commit -m "Classify each flow on first packet (tsCapable bit)"
```

---

## Task 10: Reorder process_packet for mode-aware dispatch

This task moves the TSopt early-return below the FlowKey/flowRec lookup so non-TS packets can fall through to the SEQ path. After this change, `--mode ts` still drops them as `no_TS`; `--mode seq` and the no-TS branch of `--mode hybrid` will reach SEQ logic added in Tasks 11 and 12.

**Files:**
- Modify: `pping.cpp`

- [ ] **Step 1: Restructure the top of `process_packet`**

The current order is:
1. find_pdu<TCP>, return if nullptr
2. search_option(TSOPT), return if absent (`no_TS++`)
3. memcpy out tsval/tsecr
4. early-return if `tsval == 0` etc.
5. build FlowKey
6. find_pdu<IP>/<IPv6>, return if neither
7. flow lookup / insert

The new order:
1. find_pdu<TCP>, return if nullptr
2. **search_option, but do NOT early-return** — capture pointer; mark `tsopt_present = (tsopt && tsopt->data_size() >= 8)`.
3. If present, memcpy out tsval/tsecr; else leave them 0.
4. Build FlowKey, IP lookup, IPv6 lookup, flow insert/lookup (unchanged).
5. **Classify** `fr->tsCapable` (move from Task 9 to here, since classification is the first thing after the flow record exists).
6. Mode dispatch: choose TS vs SEQ vs drop.
7. TS path runs the existing `tsval == 0 || tsecr == 0 && !SYN` check before doing TS work.

Concretely, replace the top of `process_packet` (everything from line 295 through `fr->last_tm = capTm;` at line 395) with:

```cpp
static void process_packet(const Packet& pkt)
{
    pktCnt++;
    const TCP* t_tcp;
    if ((t_tcp = pkt.pdu()->find_pdu<TCP>()) == nullptr) {
        not_tcp++;
        return;
    }

    // Probe for TCP timestamp option; do not early-return on absence.
    const auto* tsopt = t_tcp->search_option(TCP::TSOPT);
    const bool  tsopt_present = (tsopt && tsopt->data_size() >= 8);
    uint32_t rcv_tsval = 0, rcv_tsecr = 0;
    if (tsopt_present) {
        uint32_t be;
        std::memcpy(&be, tsopt->data_ptr(),     4); rcv_tsval = ntohl(be);
        std::memcpy(&be, tsopt->data_ptr() + 4, 4); rcv_tsecr = ntohl(be);
    }

    // FlowKey + IP/IPv6 selection (unchanged)
    FlowKey fk;
    const IP* ip;
    const IPv6* ipv6;
    if ((ip = pkt.pdu()->find_pdu<IP>()) != nullptr) {
        uint32_t s = ip->src_addr();
        uint32_t d = ip->dst_addr();
        std::memcpy(fk.srcIP.data(), &s, 4);
        std::memcpy(fk.dstIP.data(), &d, 4);
        fk.af = 4;
    } else if ((ipv6 = pkt.pdu()->find_pdu<IPv6>()) != nullptr) {
        IPv6Address sa = ipv6->src_addr();
        IPv6Address da = ipv6->dst_addr();
        std::copy(sa.begin(), sa.end(), fk.srcIP.begin());
        std::copy(da.begin(), da.end(), fk.dstIP.begin());
        fk.af = 6;
    } else {
        not_v4or6++;
        return;
    }
    fk.sport = t_tcp->sport();
    fk.dport = t_tcp->dport();

    // capture clock time (unchanged)
    std::time_t result = pkt.timestamp().seconds();
    if (offTm < 0) {
        offTm = static_cast<int64_t>(pkt.timestamp().seconds());
        startm = double(pkt.timestamp().microseconds()) * 1e-6;
        capTm = startm;
        if (sumInt) {
            std::cerr << "First packet at "
                      << std::asctime(std::localtime(&result)) << "\n";
        }
    } else {
        int64_t tt = static_cast<int64_t>(pkt.timestamp().seconds()) - offTm;
        capTm = double(tt) + double(pkt.timestamp().microseconds()) * 1e-6;
    }
    (void)result; // human-format time is reformatted inside emit()

    const FlowKey rk = fk.reversed();

    auto fres = flows.try_emplace(fk, nullptr);
    auto fit = fres.first;
    bool inserted = fres.second;
    flowRec* fr;
    if (inserted) {
        if (flowCnt >= maxFlows) {
            std::cerr << "flow limit (" << maxFlows << ") reached, dropping new flow: "
                      << flowKeyName(fk) << "\n";
            flows.erase(fit);
            return;
        }
        fr = new flowRec();
        fit->second = fr;
        flowCnt++;
        auto rit = flows.find(rk);
        if (rit != flows.end()) {
            rit->second->revFlow = true;
            fr->revFlow = true;
        }
    } else {
        fr = fit->second;
    }
    fr->last_tm = capTm;

    // Classify the flow on its first packet (set once, never changes).
    if (!fr->classified) {
        fr->tsCapable = tsopt_present;
        fr->classified = true;
    }

    if (!fr->revFlow) {
        uniDir++;
        return;
    }
    double arr_fwd = fr->bytesSnt + pkt.pdu()->size();
    fr->bytesSnt = arr_fwd;

    // Mode dispatch.
    const bool useSeq =
        (mode == Mode::SEQ) ||
        (mode == Mode::HYBRID && !fr->tsCapable);
    const bool useTs =
        (mode == Mode::TS && fr->tsCapable) ||
        (mode == Mode::HYBRID && fr->tsCapable);

    if (mode == Mode::TS && !fr->tsCapable) {
        // Today's behavior in --mode ts: count and drop.
        no_TS++;
        return;
    }

    bool toLocal = filtLocal && localIPaf == fk.af
                && std::memcmp(localIPBytes.data(), fk.dstIP.data(), 16) == 0;

    if (useTs) {
        // Existing TS path: preserves the rcv_tsval / rcv_tsecr sanity checks.
        if (rcv_tsval == 0 || (rcv_tsecr == 0 && (t_tcp->flags() != TCP::SYN))) {
            return;
        }
        if (!toLocal) {
            TsKey tk;
            tk.flow = fk;
            tk.tsval = rcv_tsval;
            addTS(tk, tsInfo{capTm, arr_fwd, fr->bytesDep});
        }
        TsKey lookup;
        lookup.flow = rk;
        lookup.tsval = rcv_tsecr;
        auto eit = tsTbl.find(lookup);
        if (eit != tsTbl.end() && eit->second.t > 0.0) {
            double t = eit->second.t;
            double rtt = capTm - t;
            if (fr->min > rtt) fr->min = rtt;
            double fBytes = eit->second.fBytes;
            double dBytes = eit->second.dBytes;
            double pBytes = arr_fwd - fr->lstBytesSnt;
            fr->lstBytesSnt = arr_fwd;
            auto rit = flows.find(rk);
            if (rit != flows.end()) rit->second->bytesDep = fBytes;
            emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');
            eit->second.t = -t;
        }
    }

    // SEQ path: filled in by Tasks 11 and 12.
    (void)useSeq;
    (void)t_tcp;
    (void)toLocal;
}
```

The TS path inside `if (useTs) { ... }` is line-for-line the previous body (just hoisted under a guard). In `--mode ts` on a TS-capable flow, behavior is bit-identical.

- [ ] **Step 2: Build and run the existing tests in default mode**

Run:
```bash
make
./pping -m -r test/known.pcap | diff -u test/known.pcap.golden -
./pping --mode ts -m -r test/known.pcap | diff -u test/known.pcap.golden -
```
Expected: both zero-diff.

- [ ] **Step 3: Run the full test suite**

Run: `make check`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add pping.cpp
git commit -m "Reorder process_packet for mode-aware dispatch (TS path preserved)"
```

---

## Task 11: SEQ-path forward state update (outstanding + retx detection)

**Files:**
- Modify: `pping.cpp`

- [ ] **Step 1: Add a `tcp_payload_len` helper**

Insert near the top of `pping.cpp` (with the other static inlines, right after `seq_geq`):

```cpp
// TCP payload length from a libtins TCP PDU. inner_pdu()->size() if present;
// otherwise zero (pure ACK / SYN / FIN / RST). Safe on truncated frames.
static inline uint32_t tcp_payload_len(const TCP* t_tcp) noexcept {
    const PDU* inner = t_tcp->inner_pdu();
    return inner ? static_cast<uint32_t>(inner->size()) : 0u;
}
```

- [ ] **Step 2: Implement the forward state update in the SEQ branch**

Replace the placeholder in `process_packet` (the `(void)useSeq; (void)t_tcp; (void)toLocal;` lines) with:

```cpp
    if (useSeq) {
        const uint32_t seq    = t_tcp->seq();
        const auto     flags  = t_tcp->flags();
        const uint32_t pay    = tcp_payload_len(t_tcp);
        const uint32_t eff_len = pay
                               + ((flags & TCP::SYN) ? 1u : 0u)
                               + ((flags & TCP::FIN) ? 1u : 0u);

        // Forward direction: open or refresh outstanding measurement
        if (eff_len > 0 && !toLocal) {
            const uint32_t end = seq + eff_len;
            if (!fr->high_seq_init) {
                // First forward data packet — seed retx baseline and open
                // the outstanding measurement on this flow.
                fr->high_seq          = end;
                fr->high_seq_init     = true;
                fr->outstanding_end   = end;
                fr->outstanding_time  = capTm;
                fr->retx_flag         = false;
            } else if (seq_lt(seq, fr->high_seq)) {
                // Retransmission of bytes already seen forward.
                if (fr->outstanding_end != 0) fr->retx_flag = true;
            } else {
                if (seq_geq(end, fr->high_seq)) fr->high_seq = end;
                if (fr->outstanding_end == 0) {
                    fr->outstanding_end  = end;
                    fr->outstanding_time = capTm;
                    fr->retx_flag        = false;
                }
                // else: in-flight data while a measurement is pending — do
                // nothing (one outstanding per direction).
            }
        }

        // Reverse-match step is added in Task 12.
    }
```

- [ ] **Step 3: Build, run, confirm no regression in TS-only mode**

Run:
```bash
make check
./pping --mode ts -m -r test/known.pcap | diff -u test/known.pcap.golden -
```
Expected: all PASS, zero diff.

- [ ] **Step 4: Run hybrid on the windows pcap and confirm SEQ state is being recorded (no output yet — match in next task)**

```bash
./pping -v --mode hybrid -r test/pcaps/dns-tcp-windows.pcap > /tmp/h.out 2>/tmp/h.err
cat /tmp/h.out         # may be empty — match step lands in Task 12
grep flows /tmp/h.err  # summary should show flows but 0 RTT samples
```
Expected: 5 flows reported in stderr; no RTT lines yet on stdout (the SEQ match is added in Task 12).

- [ ] **Step 5: Commit**

```bash
git add pping.cpp
git commit -m "SEQ path: track outstanding measurement and retx flag (forward direction)"
```

---

## Task 12: SEQ-path reverse-direction match and emit

**Files:**
- Modify: `pping.cpp`

- [ ] **Step 1: Add the reverse match block immediately after the forward state update (still inside the `if (useSeq)` block from Task 11)**

```cpp
        // Reverse direction: ACK that crosses the outstanding boundary closes
        // the in-flight measurement on the forward (reverse-of-this-packet) flow.
        if (flags & TCP::ACK) {
            const uint32_t ack = t_tcp->ack_seq();
            auto rit = flows.find(rk);
            if (rit != flows.end()) {
                flowRec* rr = rit->second;
                if (rr->outstanding_end != 0 && seq_geq(ack, rr->outstanding_end)) {
                    const double rtt        = capTm - rr->outstanding_time;
                    const bool   karn_clean = !rr->retx_flag;
                    rr->outstanding_end = 0;
                    rr->retx_flag       = false;
                    if (karn_clean) {
                        if (rr->min > rtt) rr->min = rtt;
                        ++seqSamples;

                        // The RTT belongs to the forward (rr) flow; emit using
                        // its key. The fk in this scope is the reverse direction.
                        FlowKey ffk = fk.reversed();
                        const double fBytes = rr->bytesSnt;
                        const double dBytes = rr->bytesDep;
                        const double pBytes = rr->bytesSnt - rr->lstBytesSnt;
                        rr->lstBytesSnt = rr->bytesSnt;
                        emit(rtt, rr, ffk, fBytes, dBytes, pBytes, /*tag=*/'s');
                    } else {
                        ++seqKarnDrops;
                    }
                }
            }
        }
```

- [ ] **Step 2: Build and run hybrid on dns-tcp-windows.pcap; expect SEQ samples**

```bash
make
./pping -v --mode hybrid -e -r test/pcaps/dns-tcp-windows.pcap | tee /tmp/h.out
```
Expected: at least one line per flow, each ending in `s` as the 12th field. 5 flows × at least 1 sample each. Stderr summary should report `seq samples` non-zero.

- [ ] **Step 3: Run hybrid on dns-tcp-linux.pcap; should emit only `t` samples**

```bash
./pping --mode hybrid -e -r test/pcaps/dns-tcp-linux.pcap | awk '{ print $12 }' | sort -u
```
Expected: a single line `t`. The TS path is preempting on every flow.

- [ ] **Step 4: Run mixed-with-retx hybrid; expect `seq_karn_drops` non-zero**

```bash
./pping -v --mode hybrid -e -r test/pcaps/mixed-with-retx.pcap > /tmp/m.out 2> /tmp/m.err
grep -E 'seq.+drops' /tmp/m.err
```
Expected: stderr summary contains `1 seq karn drops` (or similar non-zero). Flow A's retx sample was discarded; flow A still gets the *clean* second sample.

- [ ] **Step 5: Run unit tests**

Run: `make check`
Expected: all PASS (golden/seq tests don't exist yet — they land in Task 14).

- [ ] **Step 6: Commit**

```bash
git add pping.cpp
git commit -m "SEQ path: match reverse ACK, emit RTT, apply strict Karn"
```

---

## Task 13: cleanUp — evict stale outstanding SEQ measurements

**Files:**
- Modify: `pping.cpp`

- [ ] **Step 1: Extend the flow-eviction loop in `cleanUp`**

In `cleanUp` (around line 477), modify the second `for` loop to also clear stale outstanding measurements. The full new loop:

```cpp
    for (auto it = flows.begin(); it != flows.end();) {
        flowRec* fr = it->second;
        if (n - fr->last_tm > flowMaxIdle) {
            delete it->second;
            it = flows.erase(it);
            flowCnt--;
            continue;
        }
        // Age out unmatched SEQ-path outstanding measurements. Same threshold
        // as the TS-path tsTbl entries.
        if (fr->outstanding_end != 0 &&
            capTm - fr->outstanding_time > tsvalMaxAge) {
            fr->outstanding_end = 0;
            fr->retx_flag       = false;
            ++seqStale;
        }
        ++it;
    }
```

- [ ] **Step 2: Build and run tests**

Run: `make check`
Expected: all PASS.

- [ ] **Step 3: Quick sanity check on hybrid-mode pcap**

Run:
```bash
./pping -v --mode hybrid -e -r test/pcaps/dns-tcp-windows.pcap > /dev/null 2> /tmp/sum.txt
cat /tmp/sum.txt
```
Expected: `seq samples` non-zero, `seq stale` may or may not appear depending on whether any flow ended without a final ACK in the fixture (it shouldn't, per fixture design).

- [ ] **Step 4: Commit**

```bash
git add pping.cpp
git commit -m "cleanUp: age out stale SEQ-path outstanding measurements (seq_stale)"
```

---

## Task 14: Generate golden files and add `test_seq.sh`

**Files:**
- Create: `test/golden/dns-tcp-linux.{ts,seq,hybrid}.golden`
- Create: `test/golden/dns-tcp-windows.{ts,seq,hybrid}.golden`
- Create: `test/golden/mixed-with-retx.{ts,seq,hybrid}.golden`
- Create: `test/test_seq.sh`
- Modify: `test/run_tests.sh`

- [ ] **Step 1: Write the golden generator inline and inspect each output before committing**

```bash
mkdir -p test/golden
for p in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
  for m in ts seq hybrid; do
    ./pping -e --mode $m -r test/pcaps/$p.pcap > test/golden/$p.$m.golden 2>/dev/null
  done
done
ls -la test/golden/
wc -l test/golden/*.golden
```

Eyeball each file. Quick sanity expectations (subject to the actual fixture timing):

| pcap                | --mode ts          | --mode seq           | --mode hybrid        |
|---------------------|--------------------|----------------------|----------------------|
| dns-tcp-linux       | non-empty, all `t` | non-empty, all `s`   | non-empty, all `t`   |
| dns-tcp-windows     | empty              | non-empty, all `s`   | non-empty, all `s`   |
| mixed-with-retx     | non-empty (flow B)  | non-empty (A,C with karn drop on A's first sample)  | mix of `t` and `s` |

If the goldens look wrong (e.g. `dns-tcp-linux` `seq` is empty when it should have samples), the fixture is the bug, not pping — fix the fixture, regenerate, retry.

- [ ] **Step 2: Write `test/test_seq.sh`**

```sh
#!/bin/sh
# test_seq.sh — diff -e --mode <m> output against goldens for SEQ/ACK feature.
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAPS_DIR="$SCRIPT_DIR/pcaps"
GOLDEN_DIR="$SCRIPT_DIR/golden"

PASS=0
FAIL=0
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built; run 'make' first"
    exit 1
fi

for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    for m in ts seq hybrid; do
        actual=$(mktemp)
        golden="$GOLDEN_DIR/$pcap.$m.golden"
        "$PPING" -e --mode "$m" -r "$PCAPS_DIR/$pcap.pcap" > "$actual" 2>/dev/null
        if diff -q "$golden" "$actual" >/dev/null 2>&1; then
            pass "$pcap/$m"
        else
            fail "$pcap/$m" "diff $golden vs actual"
            diff -u "$golden" "$actual" | head -40
        fi
        rm -f "$actual"
    done
done

TOTAL=$((PASS + FAIL))
echo ""
echo "test_seq: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
```

- [ ] **Step 3: Wire `test_seq.sh` into the master runner**

In `test/run_tests.sh`, add a line after the existing `run_test "$SCRIPT_DIR/test_format.sh"` call:

```sh
run_test "$SCRIPT_DIR/test_seq.sh"
```

- [ ] **Step 4: Make the script executable and run the suite**

```bash
chmod +x test/test_seq.sh
make check
```
Expected: 9 new PASS lines (`test_seq` 9/9). If any fail, fix the fixture or the implementation, regenerate goldens, and re-run.

- [ ] **Step 5: Commit**

```bash
git add test/golden/*.golden test/test_seq.sh test/run_tests.sh
git commit -m "Add 9 golden files and test_seq.sh for SEQ/ACK paths"
```

---

## Task 15: Cross-mode parity test for the TS-only fixture

**Files:**
- Create: `test/cross_mode_check.sh`
- Modify: `test/run_tests.sh`

- [ ] **Step 1: Write `test/cross_mode_check.sh`**

```sh
#!/bin/sh
# cross_mode_check.sh — assert TS-only flows produce identical samples in
# --mode ts and --mode hybrid (modulo the tag column, which is 't' in both).
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAP="$SCRIPT_DIR/pcaps/dns-tcp-linux.pcap"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

TS=$(mktemp); HY=$(mktemp)
trap 'rm -f "$TS" "$HY"' EXIT INT TERM

"$PPING" -e --mode ts     -r "$PCAP" > "$TS" 2>/dev/null
"$PPING" -e --mode hybrid -r "$PCAP" > "$HY" 2>/dev/null

if diff -q "$TS" "$HY" >/dev/null 2>&1; then
    printf 'PASS cross_mode_parity_dns_tcp_linux\n'
else
    printf 'FAIL cross_mode_parity_dns_tcp_linux: diff between --mode ts and --mode hybrid\n'
    diff -u "$TS" "$HY" | head -40
    exit 1
fi

# Sanity: every line must end in tag 't' (no SEQ samples on a TS-capable pcap).
BAD=$(awk '$12 != "t" { print NR": "$12 }' "$HY")
if [ -z "$BAD" ]; then
    printf 'PASS cross_mode_hybrid_all_t_tags\n'
else
    printf 'FAIL cross_mode_hybrid_all_t_tags: %s\n' "$BAD"
    exit 1
fi

exit 0
```

- [ ] **Step 2: Wire into the runner and run**

Add to `test/run_tests.sh` after the `test_seq.sh` line:

```sh
run_test "$SCRIPT_DIR/cross_mode_check.sh"
```

```bash
chmod +x test/cross_mode_check.sh
make check
```
Expected: both PASS lines present.

- [ ] **Step 3: Commit**

```bash
git add test/cross_mode_check.sh test/run_tests.sh
git commit -m "Add cross-mode parity test (--mode ts == --mode hybrid on TS-only pcap)"
```

---

## Task 16: Performance benchmark script

**Files:**
- Create: `test/bench.sh`
- Modify: `Makefile` (add a `pcaps` target so contributors can regen fixtures)

This is **not** a CI gate — it's a developer tool that prints a table.

- [ ] **Step 1: Write `test/bench.sh`**

```sh
#!/bin/sh
# bench.sh — print ns/pkt + Mpps for each (pcap, mode) pair.
# pping's wall-clock summary is the source of these numbers; this script
# just runs the matrix and tabulates.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAPS_DIR="$SCRIPT_DIR/pcaps"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

printf '%-22s %-8s %-12s %-10s\n' pcap mode ns/pkt Mpps
printf '%-22s %-8s %-12s %-10s\n' '----' '----' '------' '----'
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    for m in ts seq hybrid; do
        # capTm-based mode is silent in pcap mode, so force a summary with -v.
        line=$("$PPING" -v --mode "$m" -r "$PCAPS_DIR/$pcap.pcap" 2>&1 1>/dev/null \
              | grep '^wall-clock')
        ns=$(echo "$line" | awk '{ for (i=1;i<=NF;i++) if ($i=="ns/pkt,") print $(i-1) }')
        mpps=$(echo "$line" | awk '{ for (i=1;i<=NF;i++) if ($i=="Mpps") print $(i-1) }')
        printf '%-22s %-8s %-12s %-10s\n' "$pcap" "$m" "${ns:-?}" "${mpps:-?}"
    done
done
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x test/bench.sh
./test/bench.sh
```
Expected: a small table with 9 rows. Numbers are tiny (<1us/pkt) because the fixtures are small; this is fine — bench.sh is a harness for the developer to point at large pcaps later.

- [ ] **Step 3: Add `make pcaps` target**

Edit `Makefile`, add at the bottom:

```make
# Regenerate test fixtures from test/synth/. Requires scapy.
pcaps:
	cd test && python3 -m synth.build
```

- [ ] **Step 4: Commit**

```bash
git add test/bench.sh Makefile
git commit -m "Add test/bench.sh and 'make pcaps' target"
```

---

## Task 17: Documentation — README, help text, CHANGELOG

**Files:**
- Modify: `pping.cpp` (help text in the `help()` function)
- Modify: `README.md`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Update `help()` in `pping.cpp`**

Add the following block just before `"  -h|--help          print help then exit\n"` (around line 655):

```cpp
"  --mode {ts,seq,hybrid}\n"
"                     RTT measurement path. (default: hybrid)\n"
"                       ts      — TCP timestamp option only (legacy behavior;\n"
"                                 flows without TSopt are dropped as no_TS).\n"
"                       seq     — TCP SEQ/ACK only; works on every TCP flow.\n"
"                       hybrid  — TS path on TS-capable flows, SEQ path on\n"
"                                 the rest. Recommended; produces samples on\n"
"                                 mixed-OS workloads (Windows, stripped TS).\n"
"                     In hybrid mode the no_TS counter reports flows handled\n"
"                     by the SEQ path, not flows dropped.\n"
"\n"
"  -e output adds a 12th field (t = TS path, s = SEQ path) per RTT line.\n"
"  Human-readable output adds a trailing [t] or [s] tag.\n"
"\n"
```

- [ ] **Step 2: Update README.md**

Add a new section after `## Examples ##`:

```markdown
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

In `--mode hybrid` the `no_TS` counter reports flows that were redirected to
the SEQ path, not flows that were dropped.
```

- [ ] **Step 3: Create CHANGELOG.md**

```markdown
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
```

- [ ] **Step 4: Build, run, eyeball the help text**

```bash
make
./pping --help 2>&1 | grep -A 10 -- '--mode'
```
Expected: the new --mode block renders cleanly.

- [ ] **Step 5: Commit**

```bash
git add pping.cpp README.md CHANGELOG.md
git commit -m "Document --mode flag, output schema change, new counters"
```

---

## Self-review (writer's checklist before handing off)

- [x] **Spec section coverage**
  - Mode flag → Task 2
  - Per-flow classification → Tasks 9, 10
  - Mode dispatch table → Task 10
  - Output schema (12th field, `[t]`/`[s]`, `-m` unchanged) → Task 8
  - Summary stats (seq_samples, seq_karn_drops, seq_stale) → Tasks 4, 11–13
  - One-outstanding-per-direction sampling → Task 11
  - Strict Karn → Tasks 11, 12
  - Wrap-safe seq comparison → Task 1
  - flowRec additions → Task 3
  - process_packet classification & dispatch → Tasks 9, 10
  - SEQ forward state → Task 11
  - SEQ reverse match → Task 12
  - emit() factor-out → Task 8
  - cleanUp() addition → Task 13
  - filtLocal interaction → Tasks 10, 11 (toLocal threaded into SEQ path; reverse-match always runs)
  - RST and IPv4 fragmentation → no special-case code per spec; covered implicitly by `eff_len == 0` and the existing `not_tcp++` path
  - Malformed packets → existing libtins guards already in place
  - Test fixtures (3 pcaps) → Tasks 5–7
  - 9 goldens → Task 14
  - Cross-mode parity → Task 15
  - Performance benchmark → Task 16
  - Migration / docs → Task 17

- [x] **Placeholder scan** — no TBD/TODO/"similar to Task N" placeholders; every code step shows the full code; "expected output" sentences accompany every check command.

- [x] **Type consistency**
  - `Mode` enum used same way in Tasks 2 and 10.
  - `outstanding_end` (uint32_t), `outstanding_time` (double), `high_seq` (uint32_t), `high_seq_init` (bool), `retx_flag` (bool), `tsCapable` (bool), `classified` (bool) — same types and names across Tasks 3, 11, 12, 13.
  - `seq_lt` / `seq_geq` defined Task 1, used Tasks 11, 12.
  - `emit()` signature `(double rtt, flowRec*, const FlowKey&, double fBytes, double dBytes, double pBytes, char tag)` consistent in Tasks 8 (definition + TS-path use) and 12 (SEQ-path use).
  - `tsopt_present` and `rcv_tsval`/`rcv_tsecr` semantics in Task 10 match how Task 9 hooks classification.
  - Counter names `seqSamples`, `seqKarnDrops`, `seqStale` consistent across Tasks 4, 11, 12, 13.

- [x] **Frequent commits** — 17 tasks, 17 commits.

- [x] **TDD where it pays** — Task 1 (helpers) is true TDD. Tasks 8/14/15 use golden-diff regression as the test bed. Pure-logic tasks like 11/12 don't have isolated unit-test surface; they're covered by golden tests.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-05-seq-ack-rtt.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
