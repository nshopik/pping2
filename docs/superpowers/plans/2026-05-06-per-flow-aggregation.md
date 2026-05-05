# Per-flow RTT aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `-a` / `--aggregate` mode that emits one row per flow per closure-or-window event instead of one line per RTT match, plus capacity-default bumps (maxFlows, maxTSvals) and a CLI knob `--flowMaxAge`.

**Architecture:** The aggregator is a state extension of the existing per-direction `flowRec`: three new fields (`n_samples`, `window_start`, `closed`). All four emission triggers (FIN, RST, idle, age-cap) are consolidated in `cleanUp` — `process_packet` only flips a bit on FIN/RST. A new `emit_aggregated()` helper handles the 9-field row format. Per-match `emit()` is suppressed in aggregator mode.

**Tech Stack:** C++17, libtins (packet parsing), libpcap, scapy (Python, for synthetic pcap fixtures), POSIX sh (test runners), libstdc++ `unordered_map`.

**Spec:** `docs/superpowers/specs/2026-05-06-per-flow-aggregation-design.md` (branch `flow-aggregate`).

---

## File map

**Modified:**
- `pping.cpp` — flowRec fields, globals, CLI parsing, hot-path edits, cleanUp dispatcher, emit_aggregated, printSummary, help text, capacity defaults
- `Makefile` — no changes expected (existing `pping`, `check`, `pcaps`, `test/unit_tests` targets cover everything)
- `test/unit_tests.cpp` — new unit tests for the aggregator
- `test/run_tests.sh` — register the new shell test
- `test/synth/build.py` — register new synth fixtures
- `README.md` — document `-a`, `--flowMaxAge`, capacity-default changes
- `CHANGELOG.md` — release-note entry

**Created:**
- `test/test_aggregate.sh` — shell test for aggregator output (golden diffs, mutual-exclusion, idle, age-cap, no-rows-when-empty)
- `test/golden/dns-tcp-linux.aggregate.golden`
- `test/golden/dns-tcp-windows.aggregate.golden`
- `test/golden/mixed-with-retx.aggregate.golden`
- `test/golden/age_cap.aggregate.golden` (synth fixture golden)
- `test/golden/idle.aggregate.golden` (synth fixture golden)
- `test/golden/no_synack.aggregate.golden` (empty file — silent-delete test)
- `test/synth/age_cap.py` — long synthetic flow spanning ~12s
- `test/synth/idle.py` — flow that goes silent mid-replay
- `test/synth/no_synack.py` — single SYN with no SYN-ACK reply

**Deleted:** none.

---

## Task 1: Bump `maxFlows` and `maxTSvals` defaults

**Files:**
- Modify: `pping.cpp:226`
- Modify: `test/unit_tests.cpp` (add new test)

- [ ] **Step 1: Write the failing test**

Append to `test/unit_tests.cpp` after `test_flowrec_seq_field_defaults` (around line 270):

```cpp
static void test_capacity_defaults()
{
    // Lock down the defaults documented in the per-flow aggregation spec.
    // These are tripwires: an accidental change should fail the test.
    ASSERT_EQ(maxFlows,  1048576);          // 1024^2
    ASSERT_EQ(maxTSvals, (size_t)268435456); // 16^7 = 2^28
}
REGISTER_TEST(test_capacity_defaults);
```

- [ ] **Step 2: Build and run unit tests; verify the new test fails**

```sh
cd /c/Users/shopik/pping && make test/unit_tests && test/unit_tests
```

Expected: `FAIL test_capacity_defaults` because `maxFlows` is still `65535` and `maxTSvals` is still `4000000`. All other tests pass.

- [ ] **Step 3: Bump `maxFlows`**

Replace in `pping.cpp` around line 226:

```cpp
static int maxFlows = 65535;
```

with:

```cpp
static int maxFlows = 1048576;   // 1024^2 — bumped per per-flow aggregation spec
```

- [ ] **Step 4: Run unit tests; only `maxTSvals` half of the test should still fail**

```sh
make test/unit_tests && test/unit_tests
```

Expected: `test_capacity_defaults` still fails on the `maxTSvals` assertion (Task 2 fixes that). Don't commit yet — bundle both bumps.

- [ ] **Step 5: Bump `maxTSvals`**

Replace in `pping.cpp` around line 231:

```cpp
static size_t maxTSvals = 4000000;
```

with:

```cpp
static size_t maxTSvals = 268435456;  // 16^7 = 2^28 — bumped per per-flow aggregation spec
```

Also update the comment block above it (lines 228-230) to reflect the new ceiling. Replace:

```cpp
// tsTbl size cap. ~830MB IPv4 / ~1.1GB IPv6 at the cap. Sized for ~4-8x
// headroom over a 100-200K pps DNS workload (typical observed peak < 2M
// entries) and ~3% of a 32GB host's RAM under hostile flood.
```

with:

```cpp
// tsTbl size cap. ~56GB IPv4 / ~74GB IPv6 at the cap (theoretical;
// real workloads at 1Mpps stay single-digit GB via tsvalMaxAge age-out).
// Sized large enough that 1Mpps captures don't hit the cap; the natural
// bound is tsvalMaxAge * (TSval-tick-rate * concurrent-TS-flows).
```

- [ ] **Step 6: Run unit tests; verify all pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: `PASS test_capacity_defaults` and all other tests pass.

- [ ] **Step 7: Commit**

```sh
git add pping.cpp test/unit_tests.cpp
git commit -m "raise maxFlows and maxTSvals defaults

maxFlows: 65535 → 1048576 (1024^2). Single-thread pping caps near
2-3 Mpps; 1M concurrent flows is well past any realistic worst case.
maxTSvals: 4M → 268435456 (16^7 = 2^28). Worst-case ~74 GB IPv6,
real workloads at 1 Mpps stay single-digit GB via tsvalMaxAge age-out.
Adds tripwire unit test."
```

---

## Task 2: Add `n_samples`, `window_start`, `closed` fields to `flowRec`

**Files:**
- Modify: `pping.cpp:156-190` (the `flowRec` class)
- Modify: `test/unit_tests.cpp` (extend `test_flowrec_seq_field_defaults`)

- [ ] **Step 1: Update the failing-defaults test to assert the new fields exist with correct defaults**

In `test/unit_tests.cpp`, replace the body of `test_flowrec_seq_field_defaults` (currently around line 258):

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
    ASSERT_EQ(fr.revFlowRec, (flowRec*)nullptr);
}
```

with:

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
    ASSERT_EQ(fr.revFlowRec, (flowRec*)nullptr);
    // Aggregator additions:
    ASSERT_EQ((int)fr.n_samples, 0);
    ASSERT_EQ(fr.window_start, 0.0);
    ASSERT_EQ(fr.closed, false);
}
```

- [ ] **Step 2: Build unit tests; verify the test fails**

```sh
make test/unit_tests
```

Expected: compile error — `flowRec` has no member `n_samples` / `window_start` / `closed`. (Compile failure counts as a failing test.)

- [ ] **Step 3: Add the three fields to `flowRec`**

In `pping.cpp`, after the existing SEQ-path state block (around line 186, just before `bool tsCapable{false}`), add:

```cpp
    // Aggregator state (used in --aggregate mode for per-flow rows).
    uint32_t n_samples    = 0;        // RTT matches counted in current window;
                                      // resets on age-cap fire.
    double   window_start = 0.;       // capTm at flow creation (or last age-cap reset).
                                      // 0.0 means "not yet seen a packet" — process_packet
                                      // sets it on the inserted branch.
    bool     closed       = false;    // first FIN observed on this direction's flowRec,
                                      // or RST observed on either direction (peer's flag
                                      // is set via revFlowRec from the RST-receiving side).
```

Place the block after `bool retx_flag{false};` and before `// Set once on first packet through process_packet, then never modified.`

- [ ] **Step 4: Build and run unit tests; verify pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: all tests pass including `test_flowrec_seq_field_defaults`.

- [ ] **Step 5: Commit**

```sh
git add pping.cpp test/unit_tests.cpp
git commit -m "flowRec: add n_samples, window_start, closed fields

Per-flow aggregator state. Defaults: n_samples=0, window_start=0,
closed=false. Total ~16 bytes per flowRec after struct padding."
```

---

## Task 3: Add aggregator and `flowMaxAge` globals

**Files:**
- Modify: `pping.cpp` around line 220-260 (the existing static-globals block)
- Modify: `test/unit_tests.cpp` (add a defaults assertion to `test_capacity_defaults`)

- [ ] **Step 1: Extend `test_capacity_defaults` to assert the new globals**

Replace the body of `test_capacity_defaults` from Task 1 with:

```cpp
static void test_capacity_defaults()
{
    ASSERT_EQ(maxFlows,  1048576);
    ASSERT_EQ(maxTSvals, (size_t)268435456);
    ASSERT_EQ(flowMaxAge, 1800.);     // new: 30 min, middle ground for ClickHouse buckets
    ASSERT_EQ(aggregateOutput, false);
    ASSERT_EQ(flowsDropped,   0);
    ASSERT_EQ(aggregatedRows, 0);
}
```

- [ ] **Step 2: Build; verify it fails (undeclared identifiers)**

```sh
make test/unit_tests
```

Expected: compile error — `flowMaxAge`, `aggregateOutput`, `flowsDropped`, `aggregatedRows` are undeclared.

- [ ] **Step 3: Add the globals to `pping.cpp`**

Find the existing block that includes `static int tsDropped;` (around line 232). Right after the `seqStale` declaration (around line 235), add:

```cpp
// Aggregator state. Off by default; -a / --aggregate enables.
static bool aggregateOutput = false;
static double flowMaxAge = 1800.;        // age-cap on per-flow accumulator (sec). 0=off.
static int flowsDropped = 0;             // new flows rejected at maxFlows cap (per summary period)
static int aggregatedRows = 0;           // -a rows emitted (per summary period)
```

- [ ] **Step 4: Build and run tests; verify pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```sh
git add pping.cpp test/unit_tests.cpp
git commit -m "globals: add aggregateOutput, flowMaxAge, flowsDropped, aggregatedRows

flowMaxAge default 1800s (30 min) per spec. Other three default to
their zero values; populated on -a parse / on cap rejection / on
emit_aggregated call respectively."
```

---

## Task 4: Wire `-a` / `--aggregate` and `--flowMaxAge` into getopt; add mutual-exclusion error

**Files:**
- Modify: `pping.cpp:716-733` (the `opts` array)
- Modify: `pping.cpp:812-844` (the `getopt_long` switch)
- Create: `test/test_cli.sh` (small CLI smoke-test runner)
- Modify: `test/run_tests.sh` to register `test_cli.sh`

- [ ] **Step 1: Write the failing CLI test**

Create `test/test_cli.sh`:

```sh
#!/bin/sh
# test_cli.sh — CLI surface tests for the aggregator flags.
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAP="$SCRIPT_DIR/known.pcap"

PASS=0
FAIL=0
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

# 1. -a alone runs without error
if "$PPING" -a -r "$PCAP" >/dev/null 2>&1; then
    pass "a_alone_ok"
else
    fail "a_alone_ok" "exit non-zero"
fi

# 2. -a -e is rejected at startup
ERR=$("$PPING" -a -e -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_e_mutex"
else
    fail "a_e_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 3. -a -m is rejected at startup
ERR=$("$PPING" -a -m -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_m_mutex"
else
    fail "a_m_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 4. --flowMaxAge=900 accepted
if "$PPING" -a --flowMaxAge=900 -r "$PCAP" >/dev/null 2>&1; then
    pass "flowMaxAge_900"
else
    fail "flowMaxAge_900" "exit non-zero"
fi

# 5. --flowMaxAge=0 (disable) accepted
if "$PPING" -a --flowMaxAge=0 -r "$PCAP" >/dev/null 2>&1; then
    pass "flowMaxAge_zero"
else
    fail "flowMaxAge_zero" "exit non-zero"
fi

# 6. --flowMaxAge=-1 rejected
ERR=$("$PPING" -a --flowMaxAge=-1 -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "flowMaxAge"; then
    pass "flowMaxAge_negative_rejected"
else
    fail "flowMaxAge_negative_rejected" "expected non-zero exit + flowMaxAge in stderr; got rc=$RC"
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "test_cli: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
```

- [ ] **Step 2: Wire `test_cli.sh` into `run_tests.sh`**

In `test/run_tests.sh`, after the existing `run_test "$SCRIPT_DIR/cross_mode_check.sh"` line (line 65), add:

```sh
run_test "$SCRIPT_DIR/test_cli.sh"
```

- [ ] **Step 3: Make the new script executable**

```sh
chmod +x test/test_cli.sh
```

- [ ] **Step 4: Build pping; run the new script; verify it fails**

```sh
make pping && sh test/test_cli.sh
```

Expected: every test fails — pping doesn't know about `-a` or `--flowMaxAge` yet, prints usage to stderr, exits non-zero. ("a_alone_ok" fails because exit is non-zero.)

- [ ] **Step 5: Add `-a` and `--flowMaxAge` to the `opts` array**

In `pping.cpp`, replace the `opts` array (around line 716):

```cpp
static struct option opts[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "read",      required_argument, nullptr, 'r' },
    { "filter",    required_argument, nullptr, 'f' },
    { "count",     required_argument, nullptr, 'c' },
    { "seconds",   required_argument, nullptr, 's' },
    { "quiet",     no_argument,       nullptr, 'q' },
    { "verbose",   no_argument,       nullptr, 'v' },
    { "showLocal", no_argument,       nullptr, 'l' },
    { "machine",   no_argument,       nullptr, 'm' },
    { "extended",  no_argument,       nullptr, 'e' },
    { "sumInt",    required_argument, nullptr, 'S' },
    { "tsvalMaxAge", required_argument, nullptr, 'M' },
    { "flowMaxIdle", required_argument, nullptr, 'F' },
    { "help",      no_argument,       nullptr, 'h' },
    { "mode",      required_argument, nullptr,  0  },   // long-only
    { 0, 0, 0, 0 }
};
```

with:

```cpp
static struct option opts[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "read",      required_argument, nullptr, 'r' },
    { "filter",    required_argument, nullptr, 'f' },
    { "count",     required_argument, nullptr, 'c' },
    { "seconds",   required_argument, nullptr, 's' },
    { "quiet",     no_argument,       nullptr, 'q' },
    { "verbose",   no_argument,       nullptr, 'v' },
    { "showLocal", no_argument,       nullptr, 'l' },
    { "machine",   no_argument,       nullptr, 'm' },
    { "extended",  no_argument,       nullptr, 'e' },
    { "aggregate", no_argument,       nullptr, 'a' },
    { "sumInt",    required_argument, nullptr, 'S' },
    { "tsvalMaxAge", required_argument, nullptr, 'M' },
    { "flowMaxIdle", required_argument, nullptr, 'F' },
    { "help",      no_argument,       nullptr, 'h' },
    { "mode",      required_argument, nullptr,  0  },   // long-only
    { "flowMaxAge", required_argument, nullptr, 0 },    // long-only
    { 0, 0, 0, 0 }
};
```

- [ ] **Step 6: Add `'a'` to the short-option string and handle parsing**

Find the `getopt_long` call (around line 812). Replace the call:

```cpp
for (int c; (c = getopt_long(argc, argv, "i:r:f:c:s:hlmqve",
                             opts, &longindex)) != -1; ) {
```

with:

```cpp
for (int c; (c = getopt_long(argc, argv, "i:r:f:c:s:hlmqvea",
                             opts, &longindex)) != -1; ) {
```

In the switch body, add a case for `'a'` after the existing `case 'e':` (around line 824):

```cpp
        case 'a': aggregateOutput = true; break;
```

In the long-only `case 0:` block (around line 829), inside the existing `if (std::strcmp(name, "mode") == 0)` chain, add an `else if` branch for `flowMaxAge`. Replace the existing block:

```cpp
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
```

with:

```cpp
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
            } else if (std::strcmp(name, "flowMaxAge") == 0) {
                double v = atof(optarg);
                if (v < 0.) {
                    std::cerr << "fatal: --flowMaxAge=" << optarg
                              << " must be >= 0 (0=disabled, default=1800)\n";
                    exit(EXIT_FAILURE);
                }
                flowMaxAge = v;
            }
            break;
        }
```

- [ ] **Step 7: Add the mutual-exclusion check after argument parsing**

Find the line `if (optind < argc || fname.empty()) {` (around line 846). Insert the mutual-exclusion guard immediately before it:

```cpp
    if (aggregateOutput && (extendedMachineOutput || machineReadable)) {
        std::cerr << "fatal: -a/--aggregate is mutually exclusive with "
                     "-e/--extended and -m/--machine\n";
        exit(EXIT_FAILURE);
    }
    if (optind < argc || fname.empty()) {
```

- [ ] **Step 8: Build pping; rerun the CLI test; verify all six checks pass**

```sh
make pping && sh test/test_cli.sh
```

Expected: `6/6 checks passed`.

- [ ] **Step 9: Commit**

```sh
git add pping.cpp test/test_cli.sh test/run_tests.sh
git commit -m "cli: add -a/--aggregate and --flowMaxAge with mutex check

-a is short and long; --flowMaxAge is long-only. Negative values
rejected. -a combined with -e or -m exits 1 with a clear message.
New shell test: test_cli.sh covers the parse + reject paths."
```

---

## Task 5: Update help text for the new flags

**Files:**
- Modify: `pping.cpp:739-801` (the `help()` function)

- [ ] **Step 1: Append a `--help`-output assertion to `test_cli.sh`**

In `test/test_cli.sh`, before the `TOTAL=$((PASS + FAIL))` line, add:

```sh
# 7. -h/--help mentions -a and --flowMaxAge
HELP=$("$PPING" --help 2>&1)
if echo "$HELP" | grep -q "\-a|--aggregate" && echo "$HELP" | grep -q "flowMaxAge"; then
    pass "help_documents_a_and_flowmaxage"
else
    fail "help_documents_a_and_flowmaxage" "help text missing -a or --flowMaxAge"
fi
```

- [ ] **Step 2: Run the test; verify it fails**

```sh
sh test/test_cli.sh
```

Expected: `help_documents_a_and_flowmaxage` fails (existing help text has neither flag).

- [ ] **Step 3: Update `help()` in `pping.cpp`**

Inside `help()` (line 739), insert two new flag descriptions. After the existing `-e|--extended` block (which ends around line 764), add the `-a` block:

```cpp
"\n"
"  -a|--aggregate     emit one row per flow per closure-or-window event\n"
"                     instead of one row per RTT match. Mutually exclusive\n"
"                     with -e and -m. Row format (9 fields, space-separated):\n"
"                       epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag\n"
"                     epoch.usec is the flow's last_tm; min_rtt is in seconds.\n"
"                     Triggers: FIN/RST close (this dir for FIN, both for RST),\n"
"                     idle expiry via --flowMaxIdle, age-cap via --flowMaxAge,\n"
"                     and shutdown flush. Designed for direct ingestion into\n"
"                     ClickHouse.\n"
```

After the existing `--flowMaxIdle` block (which ends around line 783), add the `--flowMaxAge` block:

```cpp
"\n"
"  --flowMaxAge num   in -a mode, emit a row and reset the per-flow accumulator\n"
"                     after the flow has been alive for <num> seconds (default\n"
"                     1800). 0 disables — long flows then flush only on FIN,\n"
"                     RST, idle, or shutdown. Negative values rejected.\n"
```

- [ ] **Step 4: Rebuild and rerun the CLI test**

```sh
make pping && sh test/test_cli.sh
```

Expected: all 7 checks pass.

- [ ] **Step 5: Commit**

```sh
git add pping.cpp test/test_cli.sh
git commit -m "help: document -a/--aggregate and --flowMaxAge

Adds usage descriptions including the row format and trigger model."
```

---

## Task 6: Add `emit_aggregated()` helper

**Files:**
- Modify: `pping.cpp` (add after `emit()` ends, around line 367)
- Modify: `test/unit_tests.cpp` (add stdout-capture-based test)

- [ ] **Step 1: Write a failing unit test that captures stdout**

Append to `test/unit_tests.cpp` after `test_cleanUp` (around line 400):

```cpp
/* -------------------------------------------------------------------------
 * emit_aggregated — formats one row to stdout in the -a / --aggregate
 * 9-field schema. Captures stdout via dup2 so we can assert the bytes.
 * ---------------------------------------------------------------------- */
#include <fcntl.h>
#include <unistd.h>

static std::string capture_stdout(std::function<void()> fn)
{
    fflush(stdout);
    int saved_fd = dup(fileno(stdout));
    FILE* tmp = tmpfile();
    if (!tmp) { perror("tmpfile"); return ""; }
    dup2(fileno(tmp), fileno(stdout));

    fn();

    fflush(stdout);
    dup2(saved_fd, fileno(stdout));
    close(saved_fd);

    rewind(tmp);
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, tmp);
    buf[n] = 0;
    fclose(tmp);
    return std::string(buf);
}

static void test_emit_aggregated_format()
{
    flowRec fr;
    fr.last_tm    = 12.345;
    fr.min        = 0.005;
    fr.n_samples  = 7;
    fr.tsCapable  = true;

    FlowKey fk = makeFlow4(192, 168, 1, 1, 10, 0, 0, 1, 1234, 80);

    int64_t saved_off = offTm;
    std::string saved_node = node;
    offTm = 1700000000;
    node = "testhost";

    std::string out = capture_stdout([&]() { emit_aggregated(&fr, fk); });

    offTm = saved_off;
    node = saved_node;

    ASSERT_STR_EQ(out,
        "1700000012.345000 0.005000 7 192.168.1.1 1234 10.0.0.1 80 testhost t\n");
}
REGISTER_TEST(test_emit_aggregated_format);

static void test_emit_aggregated_seq_tag()
{
    flowRec fr;
    fr.last_tm    = 5.0;
    fr.min        = 0.012;
    fr.n_samples  = 3;
    fr.tsCapable  = false;     // SEQ-only flow

    FlowKey fk = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);

    int64_t saved_off = offTm;
    std::string saved_node = node;
    offTm = 0;
    node = "h";

    std::string out = capture_stdout([&]() { emit_aggregated(&fr, fk); });

    offTm = saved_off;
    node = saved_node;

    ASSERT_STR_EQ(out,
        "5.000000 0.012000 3 10.0.0.1 1 10.0.0.2 2 h s\n");
}
REGISTER_TEST(test_emit_aggregated_seq_tag);
```

- [ ] **Step 2: Build; verify the test fails**

```sh
make test/unit_tests
```

Expected: compile error — `emit_aggregated` is undeclared.

- [ ] **Step 3: Add `emit_aggregated` to `pping.cpp`**

In `pping.cpp`, after the `emit()` function ends (around line 367), insert:

```cpp
// Aggregator output helper — emits one row per flow per closure-or-window event.
// Called only from cleanUp; invariant: caller has verified n_samples > 0 and
// aggregateOutput == true. Row timestamp uses fr->last_tm (not capTm at the
// cleanUp tick) so emission time matches the last packet seen on this flow.
// Format: "epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag\n"
static void emit_aggregated(const flowRec* fr, const FlowKey& fk)
{
    std::string ipsstr = ipToString(fk.srcIP, fk.af);
    std::string ipdstr = ipToString(fk.dstIP, fk.af);
    printf("%" PRId64 ".%06d %.6f %u %s %u %s %u %s %c\n",
           int64_t(fr->last_tm + offTm),
           int((fr->last_tm - floor(fr->last_tm)) * 1e6),
           fr->min, fr->n_samples,
           ipsstr.c_str(), fk.sport,
           ipdstr.c_str(), fk.dport,
           node.c_str(),
           fr->tsCapable ? 't' : 's');
    int64_t now = clock_now();
    if (now - nextFlush >= 0) {
        nextFlush = now + flushInt;
        fflush(stdout);
    }
}
```

- [ ] **Step 4: Build and run unit tests; verify pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: `test_emit_aggregated_format` and `test_emit_aggregated_seq_tag` both pass.

- [ ] **Step 5: Commit**

```sh
git add pping.cpp test/unit_tests.cpp
git commit -m "emit_aggregated: helper for -a row format

Nine fields, space-separated. Timestamp uses fr->last_tm so emission
time matches the last observed packet — invariant under the cleanUp
tick latency. Unit tests cover both 't' and 's' tag paths."
```

---

## Task 7: cleanUp dispatcher — `closed` branch (FIN/RST sweep)

**Files:**
- Modify: `pping.cpp:592-623` (the `cleanUp` function)
- Modify: `test/unit_tests.cpp` (extend `test_cleanUp` or add new test)

- [ ] **Step 1: Add a unit test for the closed-branch behavior**

Append to `test/unit_tests.cpp` after `test_cleanUp`:

```cpp
static void test_cleanUp_closed_emits_and_deletes()
{
    flows.clear();
    tsTbl.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    // Save & set globals
    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 100.0;

    // Closed flow with samples — should emit + delete
    FlowKey f1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr1 = new flowRec();
    fr1->last_tm = 50.0;
    fr1->min = 0.001;
    fr1->n_samples = 4;
    fr1->closed = true;
    fr1->tsCapable = true;
    fr1->window_start = 10.0;
    flows[f1] = fr1;
    flowCnt = 1;

    // Closed flow with no samples — should silently delete (no emit)
    FlowKey f2 = makeFlow4(10, 0, 0, 3, 10, 0, 0, 4, 1, 2);
    flowRec* fr2 = new flowRec();
    fr2->last_tm = 50.0;
    fr2->min = 1e30;
    fr2->n_samples = 0;
    fr2->closed = true;
    flows[f2] = fr2;
    flowCnt = 2;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // Both deleted
    ASSERT_EQ(flows.count(f1), 0u);
    ASSERT_EQ(flows.count(f2), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 1);

    // Output: exactly one line for f1
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    // Restore
    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_closed_emits_and_deletes);
```

- [ ] **Step 2: Build and run; verify the test fails**

```sh
make test/unit_tests && test/unit_tests
```

Expected: `test_cleanUp_closed_emits_and_deletes` fails — current cleanUp doesn't honour the `closed` field at all (treats f1 and f2 as non-idle, leaves them in the table).

- [ ] **Step 3: Rewrite `cleanUp` with the dispatcher**

Replace the entire `cleanUp` function in `pping.cpp` (around line 592) with:

```cpp
static void cleanUp(double n, bool flush_all = false)
{
    // erase entry if its TSval was seen more than tsvalMaxAge
    // seconds in the past.
    for (auto it = tsTbl.begin(); it != tsTbl.end();) {
        if (capTm - std::abs(it->second.t) > tsvalMaxAge) {
            it = tsTbl.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = flows.begin(); it != flows.end();) {
        flowRec* fr = it->second;

        // Determine emission reason. Priority: shutdown-flush > closed > idle > age-cap.
        // shutdown-flush emits any flow with samples regardless of trigger.
        bool emit_now    = false;
        bool delete_after = false;
        bool reset_window = false;

        if (flush_all) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (fr->closed) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (n - fr->last_tm > flowMaxIdle) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            delete_after = true;
        } else if (flowMaxAge > 0. && capTm - fr->window_start > flowMaxAge) {
            emit_now = aggregateOutput && fr->n_samples > 0;
            reset_window = true;
        }

        if (emit_now) {
            emit_aggregated(fr, it->first);
            ++aggregatedRows;
        }

        if (delete_after) {
            // Unlink peer's cached pointer before delete to avoid dangling.
            if (fr->revFlowRec) fr->revFlowRec->revFlowRec = nullptr;
            delete fr;
            it = flows.erase(it);
            flowCnt--;
            continue;
        }

        if (reset_window) {
            fr->n_samples    = 0;
            fr->min          = 1e30;
            fr->window_start = capTm;
            fr->lstBytesSnt  = fr->bytesSnt;
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
}
```

- [ ] **Step 4: Build and run; verify the new test passes and existing tests still pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: all tests pass, including `test_cleanUp` (idle eviction unchanged) and `test_cleanUp_closed_emits_and_deletes`.

- [ ] **Step 5: Commit**

```sh
git add pping.cpp test/unit_tests.cpp
git commit -m "cleanUp: dispatcher for close/idle/age-cap/flush-all

Single emit site for all four aggregator triggers. Closed flag
priority over idle; idle priority over age-cap. n_samples=0 means
silent delete (no row). flush_all parameter (default false) is for
the shutdown path. Iterator safety preserved: age-cap reset doesn't
invalidate, only delete branches do via flows.erase."
```

---

## Task 8: cleanUp dispatcher — idle and age-cap branches

**Files:**
- Modify: `test/unit_tests.cpp` (add idle and age-cap branch tests)

The dispatcher already covers these branches from Task 7; this task locks down the behavior with explicit tests.

- [ ] **Step 1: Add tests for idle and age-cap branches**

Append to `test/unit_tests.cpp`:

```cpp
static void test_cleanUp_idle_with_samples_emits()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 1000.0;

    // Idle flow with samples — emits + deletes.
    // flowMaxIdle = 300 by default; idle = 1000 - 600 = 400 > 300.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 600.0;
    fr->min = 0.002;
    fr->n_samples = 5;
    fr->tsCapable = true;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    ASSERT_EQ(flows.count(f), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 1);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_idle_with_samples_emits);

static void test_cleanUp_idle_zero_samples_silent_delete()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    bool saved_agg = aggregateOutput;
    aggregateOutput = true;
    capTm = 1000.0;

    // Idle flow with zero samples — silently deleted, no emit.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 600.0;
    fr->n_samples = 0;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    ASSERT_EQ(flows.count(f), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 0);
    ASSERT_STR_EQ(out, "");

    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_idle_zero_samples_silent_delete);

static void test_cleanUp_age_cap_resets_window_keeps_tcp_state()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    double saved_age = flowMaxAge;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    flowMaxAge = 100.;     // small for the test
    capTm = 200.0;

    // Active flow — packets recent, but window started long ago.
    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 195.0;        // recent — not idle
    fr->window_start = 50.0;    // 200 - 50 = 150 > flowMaxAge (100): cap fires
    fr->min = 0.003;
    fr->n_samples = 9;
    fr->tsCapable = true;
    // Some TCP state we expect to be preserved:
    fr->high_seq = 12345;
    fr->high_seq_init = true;
    fr->outstanding_end = 67890;
    fr->outstanding_time = 195.0;
    fr->bytesSnt = 1000.0;
    fr->lstBytesSnt = 800.0;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // Flow still in table
    ASSERT_EQ(flows.count(f), 1u);
    ASSERT_EQ(flowCnt, 1);
    ASSERT_EQ(aggregatedRows, 1);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 1);

    flowRec* alive = flows[f];
    // Aggregator state reset:
    ASSERT_EQ((int)alive->n_samples, 0);
    ASSERT_EQ(alive->min, 1e30);
    ASSERT_EQ(alive->window_start, capTm);
    ASSERT_EQ(alive->lstBytesSnt, alive->bytesSnt);
    // TCP state preserved:
    ASSERT_EQ((int)alive->high_seq, 12345);
    ASSERT_EQ(alive->high_seq_init, true);
    ASSERT_EQ((int)alive->outstanding_end, 67890);
    ASSERT_EQ(alive->outstanding_time, 195.0);
    ASSERT_EQ(alive->bytesSnt, 1000.0);

    delete flows[f];
    flows.clear();
    flowCnt = 0;
    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
    flowMaxAge = saved_age;
}
REGISTER_TEST(test_cleanUp_age_cap_resets_window_keeps_tcp_state);

static void test_cleanUp_age_cap_disabled_when_zero()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    bool saved_agg = aggregateOutput;
    double saved_age = flowMaxAge;
    aggregateOutput = true;
    flowMaxAge = 0.;       // disabled
    capTm = 1e9;           // very large

    FlowKey f = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr = new flowRec();
    fr->last_tm = 1e9 - 1.;     // recent
    fr->window_start = 0.0;     // long-ago — would cap-fire if cap were enabled
    fr->n_samples = 5;
    flows[f] = fr;
    flowCnt = 1;

    std::string out = capture_stdout([&]() { cleanUp(capTm); });

    // No emit, no reset.
    ASSERT_EQ(aggregatedRows, 0);
    ASSERT_STR_EQ(out, "");
    ASSERT_EQ(flows[f]->window_start, 0.0);   // untouched
    ASSERT_EQ((int)flows[f]->n_samples, 5);

    delete flows[f];
    flows.clear();
    flowCnt = 0;
    aggregateOutput = saved_agg;
    flowMaxAge = saved_age;
}
REGISTER_TEST(test_cleanUp_age_cap_disabled_when_zero);
```

- [ ] **Step 2: Build and run; verify all four new tests pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```sh
git add test/unit_tests.cpp
git commit -m "test: lock down cleanUp idle and age-cap branches

Four scenarios: idle-with-samples emit, idle-zero-samples silent
delete, age-cap reset preserves TCP state, age-cap=0 disables."
```

---

## Task 9: cleanUp shutdown-flush variant

**Files:**
- Modify: `test/unit_tests.cpp` (add a test for `flush_all=true`)

The `flush_all` parameter was added in Task 7; this task verifies it works correctly.

- [ ] **Step 1: Add the shutdown-flush test**

Append to `test/unit_tests.cpp`:

```cpp
static void test_cleanUp_flush_all_drains_active_flows()
{
    flows.clear();
    flowCnt = 0;
    aggregatedRows = 0;

    int64_t saved_off = offTm;
    std::string saved_node = node;
    bool saved_agg = aggregateOutput;
    offTm = 0;
    node = "h";
    aggregateOutput = true;
    capTm = 100.0;

    // Three active (non-idle, non-closed, no age-cap) flows.
    // f1, f2 have samples (should emit), f3 has zero (silent delete).
    FlowKey f1 = makeFlow4(10, 0, 0, 1, 10, 0, 0, 2, 1, 2);
    flowRec* fr1 = new flowRec();
    fr1->last_tm = 99.0; fr1->min = 0.001; fr1->n_samples = 3; fr1->tsCapable = true;
    flows[f1] = fr1;

    FlowKey f2 = makeFlow4(10, 0, 0, 3, 10, 0, 0, 4, 3, 4);
    flowRec* fr2 = new flowRec();
    fr2->last_tm = 99.5; fr2->min = 0.002; fr2->n_samples = 7; fr2->tsCapable = false;
    flows[f2] = fr2;

    FlowKey f3 = makeFlow4(10, 0, 0, 5, 10, 0, 0, 6, 5, 6);
    flowRec* fr3 = new flowRec();
    fr3->last_tm = 99.0; fr3->n_samples = 0;
    flows[f3] = fr3;

    flowCnt = 3;

    std::string out = capture_stdout([&]() { cleanUp(capTm, /*flush_all=*/true); });

    // All three deleted. Two emitted.
    ASSERT_EQ(flows.size(), 0u);
    ASSERT_EQ(flowCnt, 0);
    ASSERT_EQ(aggregatedRows, 2);
    int newlines = 0;
    for (char c : out) if (c == '\n') ++newlines;
    ASSERT_EQ(newlines, 2);

    offTm = saved_off;
    node = saved_node;
    aggregateOutput = saved_agg;
}
REGISTER_TEST(test_cleanUp_flush_all_drains_active_flows);
```

- [ ] **Step 2: Build and run; verify pass**

```sh
make test/unit_tests && test/unit_tests
```

Expected: `test_cleanUp_flush_all_drains_active_flows` passes.

- [ ] **Step 3: Commit**

```sh
git add test/unit_tests.cpp
git commit -m "test: cleanUp(flush_all=true) drains active flows on shutdown

Active (non-idle, non-closed) flows with samples emit; zero-sample
flows silently delete; everything is removed from the table."
```

---

## Task 10: Set `window_start` on flow creation in `process_packet`

**Files:**
- Modify: `pping.cpp:416-441` (the `try_emplace` / `inserted` branch)

This is a 1-line hot-path change. No unit test (process_packet needs libtins Packet construction); validation comes from the integration tests in later tasks.

- [ ] **Step 1: Add the line**

In `pping.cpp`, find the `inserted` branch in `process_packet` (around line 420):

```cpp
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
        // Reverse-flow lookup runs only on first-packet-of-flow, not per-packet.
```

Replace `fr = new flowRec();` with:

```cpp
        fr = new flowRec();
        fr->window_start = capTm;
```

- [ ] **Step 2: Build pping; verify it compiles cleanly**

```sh
make pping
```

Expected: no errors / warnings.

- [ ] **Step 3: Run all existing tests; verify no regressions**

```sh
make check
```

Expected: every pass-count matches the pre-change baseline.

- [ ] **Step 4: Commit**

```sh
git add pping.cpp
git commit -m "process_packet: set window_start on flow creation

Required by the age-cap branch in cleanUp. Set once on the inserted
branch; never modified except by age-cap reset."
```

---

## Task 11: Detect FIN/RST in `process_packet` and set `closed` bit

**Files:**
- Modify: `pping.cpp` around line 465 (after the `if (!fr->revFlow) { uniDir++; return; }` block)

- [ ] **Step 1: Add the FIN/RST detection block**

In `pping.cpp`, find the block (around line 465-470):

```cpp
    if (!fr->revFlow) {
        uniDir++;
        return;
    }
    double arr_fwd = fr->bytesSnt + pkt.pdu()->size();
    fr->bytesSnt = arr_fwd;
```

Insert the close detection between these:

```cpp
    if (!fr->revFlow) {
        uniDir++;
        return;
    }
    // Close-flag detection. FIN is unidirectional in TCP — A's FIN closes A→B
    // but B may still send. RST kills both directions; propagate to the peer
    // flowRec via the cached pointer (null-checked since the peer may have
    // been idle-evicted earlier).
    {
        const auto cflags = t_tcp->flags();
        if (cflags & TCP::FIN) {
            fr->closed = true;
        }
        if (cflags & TCP::RST) {
            fr->closed = true;
            if (fr->revFlowRec) fr->revFlowRec->closed = true;
        }
    }
    double arr_fwd = fr->bytesSnt + pkt.pdu()->size();
    fr->bytesSnt = arr_fwd;
```

- [ ] **Step 2: Build and run all existing tests**

```sh
make check
```

Expected: every test still passes (the new bit is set but not yet read by anything observable in non-aggregator mode).

- [ ] **Step 3: Commit**

```sh
git add pping.cpp
git commit -m "process_packet: detect FIN/RST, set closed bit

FIN sets closed only on this direction's flowRec. RST sets it on
both via the cached revFlowRec pointer (null-safe). Two cheap branches
on the hot path; no allocations, no map lookups."
```

---

## Task 12: Increment `n_samples` on TS-match and SEQ-match

**Files:**
- Modify: `pping.cpp:507` (TS path) and `pping.cpp:573` (SEQ path)

- [ ] **Step 1: Add the TS-path increment**

In `pping.cpp`, find the TS-match block (around line 504-522). Replace:

```cpp
        auto eit = tsTbl.find(lookup);
        if (eit != tsTbl.end() && eit->second.t > 0.0) {
            double t = eit->second.t;
            double rtt = capTm - t;
            if (fr->min > rtt) fr->min = rtt;
```

with:

```cpp
        auto eit = tsTbl.find(lookup);
        if (eit != tsTbl.end() && eit->second.t > 0.0) {
            double t = eit->second.t;
            double rtt = capTm - t;
            if (fr->min > rtt) fr->min = rtt;
            ++fr->n_samples;   // aggregator: count this match in the current window
```

- [ ] **Step 2: Add the SEQ-path increment**

Find the SEQ-match Karn-clean block (around line 572-583). Replace:

```cpp
                if (karn_clean) {
                    if (rr->min > rtt) rr->min = rtt;
                    ++seqSamples;
```

with:

```cpp
                if (karn_clean) {
                    if (rr->min > rtt) rr->min = rtt;
                    ++rr->n_samples;   // aggregator: count this match on the data-carrying flowRec
                    ++seqSamples;
```

- [ ] **Step 3: Build and run existing tests**

```sh
make check
```

Expected: no regressions.

- [ ] **Step 4: Commit**

```sh
git add pping.cpp
git commit -m "process_packet: increment n_samples on TS and SEQ matches

TS path credits fr (the ECR-receiving direction, matching where min
is updated). SEQ path credits rr (the data direction, matching the
existing seqSamples and min update). One add per match, no new
control-flow branches."
```

---

## Task 13: Suppress per-match `emit()` when `aggregateOutput`

**Files:**
- Modify: `pping.cpp:521` (TS path) and `pping.cpp:583` (SEQ path)

- [ ] **Step 1: Guard the TS-path emit call**

In `pping.cpp`, find the TS-match emit (around line 521). Replace:

```cpp
            if (fr->revFlowRec) fr->revFlowRec->bytesDep = fBytes;
            emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');
            eit->second.t = -t;
```

with:

```cpp
            if (fr->revFlowRec) fr->revFlowRec->bytesDep = fBytes;
            if (!aggregateOutput) {
                emit(rtt, fr, fk, fBytes, dBytes, pBytes, /*tag=*/'t');
            }
            eit->second.t = -t;
```

- [ ] **Step 2: Guard the SEQ-path emit call**

Find the SEQ-path Karn-clean emit (around line 583). Replace:

```cpp
                    rr->lstBytesSnt = rr->bytesSnt;
                    emit(rtt, rr, ffk, fBytes, dBytes, pBytes, /*tag=*/'s');
                } else {
                    ++seqKarnDrops;
                }
```

with:

```cpp
                    rr->lstBytesSnt = rr->bytesSnt;
                    if (!aggregateOutput) {
                        emit(rtt, rr, ffk, fBytes, dBytes, pBytes, /*tag=*/'s');
                    }
                } else {
                    ++seqKarnDrops;
                }
```

- [ ] **Step 3: Verify non-aggregator output is unchanged via existing tests**

```sh
make check
```

Expected: every test still passes — `-e`, `-m`, default human output, all SEQ/ACK goldens are byte-identical.

- [ ] **Step 4: Verify aggregator mode produces output (smoke test)**

```sh
./pping -a -r test/known.pcap | head -5
```

Expected: lines beginning with epoch.usec timestamps containing the new 9-field aggregated row format. (Exact output validated in Task 17.)

- [ ] **Step 5: Commit**

```sh
git add pping.cpp
git commit -m "process_packet: suppress per-match emit() in -a mode

Guards both TS-path and SEQ-path emit calls behind !aggregateOutput.
The min and n_samples updates still happen — only the printf is
skipped, so the cleanUp aggregator gets correct accumulator values."
```

---

## Task 14: Update `printSummary` for new counters and remove per-rejection stderr

**Files:**
- Modify: `pping.cpp:701-714` (the `printSummary` function)
- Modify: `pping.cpp:421-427` (the cap-rejection branch in `process_packet`)
- Modify: `pping.cpp:938-950` (the summary-reset block in `main`)

- [ ] **Step 1: Extend `printSummary` to include the new counters**

Replace the existing `printSummary` (line 701):

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

with:

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
                 printnz(aggregatedRows, " aggregated rows, ") +
                 printnz(flowsDropped, " flows dropped (cap), ") +
                 "\n";
}
```

- [ ] **Step 2: Replace the per-rejection stderr line with a counter increment**

In `pping.cpp` find the cap-rejection branch in `process_packet` (around line 421):

```cpp
    if (inserted) {
        if (flowCnt >= maxFlows) {
            std::cerr << "flow limit (" << maxFlows << ") reached, dropping new flow: "
                      << flowKeyName(fk) << "\n";
            flows.erase(fit);
            return;
        }
```

Replace with:

```cpp
    if (inserted) {
        if (flowCnt >= maxFlows) {
            // Cap rejection — increment counter; the per-packet stderr line
            // was removed because at high pps it would flood stderr. Counter
            // surfaces in printSummary as "<n> flows dropped (cap),".
            ++flowsDropped;
            flows.erase(fit);
            return;
        }
```

- [ ] **Step 3: Reset the new counters at each summary interval**

Find the summary-reset block in `main` (around line 938):

```cpp
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
```

Replace with:

```cpp
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
                aggregatedRows = 0;
                flowsDropped = 0;
            }
```

- [ ] **Step 4: Build and run existing tests**

```sh
make check
```

Expected: no regressions. (None of the existing tests hit the maxFlows cap at the new 1M default.)

- [ ] **Step 5: Verify the new counters surface (smoke test)**

```sh
./pping -a -v -r test/known.pcap 2>&1 >/dev/null | grep aggregated
```

Expected: a stderr line containing "aggregated rows," with a non-zero count.

- [ ] **Step 6: Commit**

```sh
git add pping.cpp
git commit -m "summary: add aggregated-rows and flows-dropped counters

aggregatedRows counts -a rows emitted. flowsDropped counts maxFlows
cap rejections (replaces the per-rejection stderr line, which would
flood stderr at high pps). Both reset per summary interval."
```

---

## Task 15: Shutdown flush in `main`

**Files:**
- Modify: `pping.cpp` around line 958 (just after the packet loop, before the wall-clock summary block)

- [ ] **Step 1: Add the final cleanUp call**

In `pping.cpp`, find the post-loop block. Just after the `for (const auto& packet : *snif) { ... }` loop ends and before the `if (!liveInp) {` wall-clock block (around line 958), insert:

```cpp
    // Aggregator shutdown flush: drain every live flow with samples to
    // guarantee no in-progress accumulator state is silently dropped on
    // graceful exit (signal, end of pcap, -c, -s, --seconds).
    if (aggregateOutput) {
        cleanUp(capTm, /*flush_all=*/true);
    }
```

- [ ] **Step 2: Add a shell test for shutdown flush**

Append to `test/test_cli.sh` before the `TOTAL=$((PASS + FAIL))` line:

```sh
# 8. -a flushes every live-at-end flow on -c cap (no measurements lost)
# Run on the existing dns-tcp-linux pcap with -c truncating mid-replay.
# We don't assert the exact count here (depends on packet ordering); we
# only assert that aggregator output is non-empty.
COUNT=$("$PPING" -a -c 20 -r "$SCRIPT_DIR/pcaps/dns-tcp-linux.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt 0 ]; then
    pass "shutdown_flush_emits_rows"
else
    fail "shutdown_flush_emits_rows" "expected non-zero output rows from -c-truncated run"
fi
```

- [ ] **Step 3: Build pping; run the shell test; verify pass**

```sh
make pping && sh test/test_cli.sh
```

Expected: 8/8 checks pass.

- [ ] **Step 4: Commit**

```sh
git add pping.cpp test/test_cli.sh
git commit -m "main: shutdown flush drains live flows in -a mode

Final cleanUp(capTm, flush_all=true) just after the packet loop.
Covers all graceful-exit paths: SIGINT/SIGTERM (loop breaks via
stopRequested), end-of-pcap, -c maxPackets, -s time_to_run."
```

---

## Task 16: Generate aggregator goldens for the three existing fixtures

**Files:**
- Create: `test/golden/dns-tcp-linux.aggregate.golden`
- Create: `test/golden/dns-tcp-windows.aggregate.golden`
- Create: `test/golden/mixed-with-retx.aggregate.golden`

These goldens are generated artefacts — run pping in aggregator mode on each fixture, sort, and write to disk. They lock down the format and content for regression detection.

- [ ] **Step 1: Generate the three goldens**

```sh
cd /c/Users/shopik/pping
./pping -a -r test/pcaps/dns-tcp-linux.pcap 2>/dev/null \
    | awk '{$8=""; gsub(/  +/, " "); print}' | sort \
    > test/golden/dns-tcp-linux.aggregate.golden
./pping -a -r test/pcaps/dns-tcp-windows.pcap 2>/dev/null \
    | awk '{$8=""; gsub(/  +/, " "); print}' | sort \
    > test/golden/dns-tcp-windows.aggregate.golden
./pping -a -r test/pcaps/mixed-with-retx.pcap 2>/dev/null \
    | awk '{$8=""; gsub(/  +/, " "); print}' | sort \
    > test/golden/mixed-with-retx.aggregate.golden
```

(`$8` is the `node` column in the 9-field aggregator format: `epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag` — column 8 is `node`. Stripping makes goldens portable across machines.)

- [ ] **Step 2: Sanity-check the goldens are non-empty and well-formed**

```sh
wc -l test/golden/*.aggregate.golden
head -3 test/golden/dns-tcp-linux.aggregate.golden
```

Expected: each file has ≥1 line. Each line: `<epoch.usec> <min_rtt> <n_samples> <srcIP> <sport> <dstIP> <dport> <tag>` (8 fields after node-stripping).

- [ ] **Step 3: Commit the goldens**

```sh
git add test/golden/*.aggregate.golden
git commit -m "test: golden files for -a / --aggregate output

Three goldens, one per existing pcap fixture, generated with
column 8 (node) stripped for portability. Wired into a new
test_aggregate.sh in the next commit."
```

---

## Task 17: Wire goldens into `test_aggregate.sh`

**Files:**
- Create: `test/test_aggregate.sh`
- Modify: `test/run_tests.sh` (register the new script)

- [ ] **Step 1: Create `test/test_aggregate.sh`**

```sh
#!/bin/sh
# test_aggregate.sh — diff -a output against goldens for the three existing
# pcap fixtures, plus invariants and synth-fixture checks.
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
    echo "ERROR: $PPING not built"
    exit 1
fi

# 1-3. Per-fixture golden diff. Strip col 8 (node/hostname) for portability.
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    actual=$(mktemp)
    golden="$GOLDEN_DIR/$pcap.aggregate.golden"
    "$PPING" -a -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null \
        | awk '{$8=""; gsub(/  +/, " "); print}' | sort \
        > "$actual"
    if diff -q "$golden" "$actual" >/dev/null 2>&1; then
        pass "aggregate_$pcap"
    else
        fail "aggregate_$pcap" "diff $golden vs actual"
        diff -u "$golden" "$actual" | head -40
    fi
    rm -f "$actual"
done

# 4. Cross-mode invariant: sum(n_samples in -a) == row count in -e for the same pcap.
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    e_rows=$("$PPING" -e -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null | wc -l | tr -d ' ')
    a_sum=$("$PPING" -a -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null \
            | awk '{s+=$3} END {print s+0}')
    if [ "$e_rows" -eq "$a_sum" ]; then
        pass "invariant_${pcap}_n_samples_eq_e_rows"
    else
        fail "invariant_${pcap}_n_samples_eq_e_rows" "e_rows=$e_rows a_sum=$a_sum"
    fi
done

TOTAL=$((PASS + FAIL))
echo ""
echo "test_aggregate: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
```

- [ ] **Step 2: Make it executable and register in `run_tests.sh`**

```sh
chmod +x test/test_aggregate.sh
```

In `test/run_tests.sh`, just after the `run_test "$SCRIPT_DIR/test_cli.sh"` line added in Task 4, add:

```sh
run_test "$SCRIPT_DIR/test_aggregate.sh"
```

- [ ] **Step 3: Run the test; verify all 6 checks pass**

```sh
sh test/test_aggregate.sh
```

Expected: `6/6 checks passed`.

- [ ] **Step 4: Run the full test suite**

```sh
make check
```

Expected: every existing test still passes plus the new ones.

- [ ] **Step 5: Commit**

```sh
git add test/test_aggregate.sh test/run_tests.sh
git commit -m "test: aggregate goldens + cross-mode invariant

Three golden diffs (one per existing pcap fixture) plus three
invariant checks: sum(n_samples in -a output) == row count in -e
output for the same pcap. Locks in 'no samples lost or
double-counted' regardless of cleanUp tick timing."
```

---

## Task 18: Synth fixture — `age_cap.pcap`

**Files:**
- Create: `test/synth/age_cap.py`
- Modify: `test/synth/build.py` (register the new fixture)

- [ ] **Step 1: Write the synth module**

Create `test/synth/age_cap.py`:

```python
"""
age_cap.pcap — single long-lived TCP flow whose capture-time spans ~12s,
designed to exercise the -a / --flowMaxAge cap with a small test value
(typically --flowMaxAge=5).

Exchange pattern repeats every 1s of capture-time:
    C → S  data (PSH-ACK, payload)        at t=1, 2, 3, ...
    S → C  ACK + small response (PSH-ACK) at t=1+RTT, 2+RTT, ...

Flow uses Linux-style TSopt so the TS path produces matches; the
window_start is set on packet 0 (SYN) and the cap fires twice within
a 12s replay when --flowMaxAge=5 is passed.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def build():
    common.seed(20260506)
    pkts = []
    base_ts = 1_000_000_000
    cip = "10.0.0.10"
    sip = "10.0.1.1"
    cport = 40000
    sport = 53
    cisn = common.isn()
    sisn = common.isn()
    cts = 1_000_000
    sts = 2_000_000

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

    # Handshake at t=0
    pkts_h = []
    pkts_h.append((C2S(cisn, 0, "S", b"", 0,
                       common.LIN_OPTS_SYN(cts)), 0.0))
    pkts_h.append((S2C(sisn, cisn + 1, "SA", b"", 1,
                       [("MSS", 1460), ("SAckOK", b""),
                        ("Timestamp", (sts, cts)),
                        ("NOP", None), ("WScale", 7)]), 0.05))
    pkts_h.append((C2S(cisn + 1, sisn + 1, "A", b"", 2,
                       common.LIN_OPTS_DATA(cts + 1, sts)), 0.10))
    for p, off in pkts_h:
        p.time = float(base_ts) + off
        pkts.append(p)

    # 12 query/response exchanges, one per second of capture-time.
    cseq = cisn + 1
    sseq = sisn + 1
    cts += 2
    sts += 1
    for i in range(1, 13):
        t = float(base_ts) + i  # +i seconds from base
        query = b"\x00\x3a" + b"\x00" * 56
        resp  = b"\x00\x4e" + b"\x00" * 76
        # query C→S
        p1 = C2S(cseq, sseq, "PA", query, 0,
                 common.LIN_OPTS_DATA(cts, sts))
        p1.time = t
        pkts.append(p1)
        # response S→C (50ms later — yields a 50ms RTT sample)
        p2 = S2C(sseq, cseq + len(query), "PA", resp, 0,
                 common.LIN_OPTS_DATA(sts, cts))
        p2.time = t + 0.050
        pkts.append(p2)
        # client ACK C→S
        p3 = C2S(cseq + len(query), sseq + len(resp), "A", b"", 0,
                 common.LIN_OPTS_DATA(cts + 1, sts))
        p3.time = t + 0.100
        pkts.append(p3)
        cseq += len(query)
        sseq += len(resp)
        cts += 2
        sts += 1

    return pkts


if __name__ == "__main__":
    common.write("age_cap.pcap", build())
```

- [ ] **Step 2: Register the new fixture in `build.py`**

Replace `test/synth/build.py`:

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

with:

```python
"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import (
    common,
    dns_tcp_linux,
    dns_tcp_windows,
    mixed_with_retx,
    age_cap,
    idle,
    no_synack,
)


def main():
    common.write("dns-tcp-linux.pcap",   dns_tcp_linux.build())
    common.write("dns-tcp-windows.pcap", dns_tcp_windows.build())
    common.write("mixed-with-retx.pcap", mixed_with_retx.build())
    common.write("age_cap.pcap",         age_cap.build())
    common.write("idle.pcap",            idle.build())
    common.write("no_synack.pcap",       no_synack.build())


if __name__ == "__main__":
    main()
```

(`idle` and `no_synack` modules are added in Tasks 19 and 20; the import will fail until those modules exist. Defer the `make pcaps` step until then.)

- [ ] **Step 3: Commit (the synth registration + age_cap module)**

```sh
git add test/synth/age_cap.py test/synth/build.py
git commit -m "synth: age_cap.pcap — long flow spanning 12s

Single TCP flow with one query/response per second over 12 seconds.
Designed to exercise --flowMaxAge=5 (the cap fires twice during
replay). build.py now also imports idle and no_synack — those
modules land in the next two commits."
```

---

## Task 19: Synth fixture — `idle.pcap`

**Files:**
- Create: `test/synth/idle.py`

- [ ] **Step 1: Write the synth module**

Create `test/synth/idle.py`:

```python
"""
idle.pcap — two flows that exercise --flowMaxIdle in -a mode.

Flow A: packets at t=0, +0.05 (RTT match). Goes silent.
Flow B: packets at t=8, +8.05 (one RTT match), keeps the capture clock
        moving so cleanUp gets called past the idle threshold.

Run with --tsvalMaxAge=1 --flowMaxIdle=2 -a: cleanUp at t≈8 evicts
Flow A (idle = 8 - 0.05 = 7.95 > 2) and emits its row using
last_tm = 0.05, NOT capTm = 8.
"""
from scapy.all import Ether, IP, TCP, Raw

from . import common


def _exchange(cip, sip, cport, sport, base_t, cts0, sts0):
    cisn = common.isn()
    sisn = common.isn()

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

    out = []
    # SYN, SYN-ACK, ACK
    out.append((C2S(cisn, 0, "S", b"",
                    common.LIN_OPTS_SYN(cts0)),                     base_t + 0.000))
    out.append((S2C(sisn, cisn + 1, "SA", b"",
                    [("MSS", 1460), ("SAckOK", b""),
                     ("Timestamp", (sts0, cts0)),
                     ("NOP", None), ("WScale", 7)]),                base_t + 0.025))
    out.append((C2S(cisn + 1, sisn + 1, "A", b"",
                    common.LIN_OPTS_DATA(cts0 + 1, sts0)),          base_t + 0.050))
    return out


def build():
    common.seed(20260507)
    pkts = []

    # Flow A: at t=0..0.05
    pkts.extend(_exchange("10.0.0.10", "10.0.1.1", 40000, 53,
                          base_t=1_000_000_000, cts0=100_000, sts0=200_000))
    # Flow B: at t=8..8.05 — keeps capture clock advancing past Flow A's idle threshold
    pkts.extend(_exchange("10.0.0.20", "10.0.1.1", 40001, 53,
                          base_t=1_000_000_008, cts0=300_000, sts0=400_000))

    # Apply timestamps stored in the (pkt, t) tuples
    out = []
    for pkt, t in pkts:
        pkt.time = t
        out.append(pkt)
    return out


if __name__ == "__main__":
    common.write("idle.pcap", build())
```

- [ ] **Step 2: Commit**

```sh
git add test/synth/idle.py
git commit -m "synth: idle.pcap — two flows for --flowMaxIdle test

Flow A at t=0..0.05 then silent. Flow B at t=8..8.05 keeps the
capture clock moving so cleanUp fires past Flow A's idle threshold.
Run with --tsvalMaxAge=1 --flowMaxIdle=2."
```

---

## Task 20: Synth fixture — `no_synack.pcap`

**Files:**
- Create: `test/synth/no_synack.py`

- [ ] **Step 1: Write the synth module**

Create `test/synth/no_synack.py`:

```python
"""
no_synack.pcap — single SYN packet with no SYN-ACK reply.

Exercises the n_samples=0 silent-delete path: in -a mode this should
produce zero output rows even after idle expiry. The flow has revFlow
== false throughout, so no RTT match is ever attempted.
"""
from scapy.all import Ether, IP, TCP

from . import common


def build():
    common.seed(20260508)
    cisn = common.isn()
    syn = Ether(src=common.CLIENT_MAC, dst=common.SERVER_MAC) / \
          IP(src="10.0.0.99", dst="10.0.1.1") / \
          TCP(sport=40099, dport=53, seq=cisn, ack=0,
              flags="S", options=common.LIN_OPTS_SYN(100_000))
    syn.time = 1_000_000_000.0
    return [syn]


if __name__ == "__main__":
    common.write("no_synack.pcap", build())
```

- [ ] **Step 2: Regenerate all pcaps and verify they exist**

```sh
make pcaps && ls test/pcaps/age_cap.pcap test/pcaps/idle.pcap test/pcaps/no_synack.pcap
```

Expected: all three files exist.

- [ ] **Step 3: Commit**

```sh
git add test/synth/no_synack.py
git commit -m "synth: no_synack.pcap — single SYN, no reply

For the n_samples=0 silent-delete test: -a mode should produce
zero output even after idle expiry."
```

---

## Task 21: Wire synth-fixture tests into `test_aggregate.sh`

**Files:**
- Modify: `test/test_aggregate.sh` (append three new tests)

- [ ] **Step 1: Append the three synth-fixture assertions**

In `test/test_aggregate.sh`, just before the final `TOTAL=$((PASS + FAIL))` block, add:

```sh
# --- Synth fixtures ---

# 7. age_cap.pcap with --flowMaxAge=5: long flow emits ≥2 rows.
ROWS=$("$PPING" -a --flowMaxAge=5 -r "$PCAPS_DIR/age_cap.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$ROWS" -ge 2 ]; then
    pass "age_cap_emits_multiple_rows"
else
    fail "age_cap_emits_multiple_rows" "expected >=2 rows; got $ROWS"
fi

# 8. idle.pcap with --tsvalMaxAge=1 --flowMaxIdle=2: silent flow A emits
#    its row using last_tm (~1e9 + 0.05), not capTm at the cleanUp tick.
#    Strip node col, sort, take only Flow A's source IP rows.
A_ROWS=$("$PPING" -a --tsvalMaxAge=1 --flowMaxIdle=2 \
            -r "$PCAPS_DIR/idle.pcap" 2>/dev/null \
         | awk '$4 == "10.0.0.10"')
A_COUNT=$(echo "$A_ROWS" | grep -c '^.')
A_TS=$(echo "$A_ROWS" | head -1 | awk '{print $1}')
if [ "$A_COUNT" -ge 1 ] && echo "$A_TS" | grep -qE '^1000000000\.0[45]'; then
    pass "idle_uses_last_tm_not_cleanup_tick"
else
    fail "idle_uses_last_tm_not_cleanup_tick" \
         "A_COUNT=$A_COUNT first_ts=$A_TS (expected 1000000000.04xxxx or .05xxxx)"
fi

# 9. no_synack.pcap: -a should produce zero output rows.
NS_ROWS=$("$PPING" -a -r "$PCAPS_DIR/no_synack.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$NS_ROWS" -eq 0 ]; then
    pass "no_synack_silent_delete"
else
    fail "no_synack_silent_delete" "expected 0 rows; got $NS_ROWS"
fi
```

- [ ] **Step 2: Run; verify all 9 checks pass**

```sh
sh test/test_aggregate.sh
```

Expected: `9/9 checks passed`.

- [ ] **Step 3: Run the full suite**

```sh
make check
```

Expected: every test passes.

- [ ] **Step 4: Commit**

```sh
git add test/test_aggregate.sh
git commit -m "test: synth-fixture assertions for -a mode

Three new checks: age_cap emits multiple rows with --flowMaxAge=5,
idle.pcap stamps rows with last_tm not the cleanUp-tick time, and
no_synack produces zero output (n_samples=0 silent delete)."
```

---

## Task 22: Performance regression check

**Files:** none (manual verification step; results recorded in commit message).

- [ ] **Step 1: Capture a baseline ns/pkt on the existing `mixed-with-retx` fixture**

```sh
./pping -e -r test/pcaps/mixed-with-retx.pcap > /dev/null
```

Read the `wall-clock: ... ns/pkt ...` line from stderr. Record the number.

- [ ] **Step 2: Capture the aggregator-mode ns/pkt**

```sh
./pping -a -r test/pcaps/mixed-with-retx.pcap > /dev/null
```

Read the same line from stderr. Record.

- [ ] **Step 3: Capture the default-mode (no flag) ns/pkt**

```sh
./pping -r test/pcaps/mixed-with-retx.pcap > /dev/null
```

Record.

- [ ] **Step 4: Verify acceptance**

Acceptance criteria:
- `-a` ns/pkt is **at most equal to** `-e` ns/pkt (printf elimination should make it noticeably cheaper).
- `-e` ns/pkt is unchanged from main (compare with `git stash` then a fresh build, if uncertain).

If `-a` regresses materially against `-e` (more than ~10%), investigate. Likely culprit: a hot-path branch that didn't exist before. Use `perf` or repeat the run with `time` for confirmation.

- [ ] **Step 5: Record the three numbers in the PR description**

No commit needed — the perf check is a sanity gate, not a tracked artefact. Note the three ns/pkt values (`-e`, `-a`, default) in the eventual PR description so reviewers can verify acceptance themselves.

---

## Task 23: README update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an Output formats subsection for `-a` after the existing `-e` section**

In `README.md`, find the `### -e — machine-readable, extended` section. After it ends (just before `## Measurement modes`), add:

````markdown
### `-a` — aggregated, one row per flow

```
epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag
```

```
1715876442.123456 0.008700 247 192.168.1.5 54321 34.107.221.82 443 host.example.com t
```

Nine space-separated fields, no quoting. One row per flow per closure-or-window event instead of one row per RTT match. Designed for direct ingestion into ClickHouse where downstream aggregation only consumes per-flow `min` RTT.

`epoch.usec` is the flow's `last_tm` (last packet time). `min_rtt` is the minimum RTT observed in this row's window. `n_samples` is the count of RTT matches contributing to `min_rtt`; useful for downstream confidence filtering. `tag` is `t` (TS path) or `s` (SEQ path), constant per flow.

Triggers: FIN (this direction's flow), RST (both directions), idle expiry via `--flowMaxIdle`, age-cap via `--flowMaxAge`, and shutdown flush. Mutually exclusive with `-e` and `-m`.

```Shell
./pping -a -r capture.pcap                     # aggregated; default age-cap = 1800s
./pping -a --flowMaxAge=900 -r capture.pcap    # 15-min windows for investigation
./pping -a --flowMaxAge=0   -r capture.pcap    # cap disabled — emit on close/idle only
```
````

- [ ] **Step 2: Add a brief note in the "What's changed from upstream" section**

In `README.md`, find the `## What's changed from upstream` list. After the existing `**Extended machine-readable output** (`-e`) — ...` bullet, add:

```markdown
- **Aggregated output mode** (`-a`/`--aggregate`) — one row per flow per
  closure or window instead of one row per RTT match. Substantially lower
  ClickHouse ingest cost on busy capture points; emit-on-close, emit-on-idle,
  emit-on-age-cap, and shutdown-flush triggers. New knob `--flowMaxAge`
  controls the per-flow rolling window (default 1800s).
```

Also adjust the existing capacity-defaults bullet, or add a new one if none exists:

```markdown
- **Higher default capacity** — `maxFlows` raised from 65535 to 1,048,576;
  `maxTSvals` raised from 4M to 256M. The per-rejection stderr line is
  replaced by a counter in the periodic summary line.
```

- [ ] **Step 3: Commit**

```sh
git add README.md
git commit -m "README: document -a/--aggregate, --flowMaxAge, capacity bumps"
```

---

## Task 24: CHANGELOG entry

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the existing CHANGELOG to match the style**

```sh
head -40 CHANGELOG.md
```

- [ ] **Step 2: Add a new top-of-file entry**

Insert at the top of `CHANGELOG.md` (under the title, before the most recent entry) — exact heading style depending on existing convention:

```markdown
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
```

If the existing CHANGELOG uses a different heading or section convention, match it exactly. (Read the most recent existing entry and mimic its layout.)

- [ ] **Step 3: Commit**

```sh
git add CHANGELOG.md
git commit -m "CHANGELOG: per-flow aggregation entry"
```

---

## Task 25: Final integration sanity-run

**Files:** none (verification only).

- [ ] **Step 1: Clean build**

```sh
make clean && make pping && make test/unit_tests
```

Expected: clean compile, no warnings.

- [ ] **Step 2: Run the full test suite**

```sh
make check
```

Expected: every test passes. Total pass count = (existing baseline) + (new tests added in this plan):
- `test_capacity_defaults` (Task 1, 3)
- `test_flowrec_seq_field_defaults` (extended in Task 2)
- `test_emit_aggregated_format`, `test_emit_aggregated_seq_tag` (Task 6)
- `test_cleanUp_closed_emits_and_deletes` (Task 7)
- `test_cleanUp_idle_with_samples_emits`, `test_cleanUp_idle_zero_samples_silent_delete`, `test_cleanUp_age_cap_resets_window_keeps_tcp_state`, `test_cleanUp_age_cap_disabled_when_zero` (Task 8)
- `test_cleanUp_flush_all_drains_active_flows` (Task 9)
- `test_cli.sh`: 8 checks (Tasks 4, 5, 15)
- `test_aggregate.sh`: 9 checks (Tasks 17, 21)

- [ ] **Step 3: Smoke-test live capture (manual, optional)**

```sh
sudo ./pping -i any -a -c 100 -v
```

Expected: aggregated rows scroll past stdout; the periodic summary line on stderr includes `aggregated rows,` once at least one flow has been emitted.

- [ ] **Step 4: Confirm the working tree is clean and the branch is ready to merge**

```sh
git status
git log --oneline master..HEAD
```

Expected: clean tree; commit history shows the per-task progression with no fixups or amends pending.

- [ ] **Step 5: Push the branch and open a PR**

(User-discretion step; the plan does not auto-push or auto-PR.)

---

## Self-review summary

**Spec coverage (sanity check against `docs/superpowers/specs/2026-05-06-per-flow-aggregation-design.md`):**

- Goals: emit one row per closure/window — Tasks 6–13. Carry only ClickHouse-consumed fields — Task 6 + 16. Cheaper-per-packet — Tasks 12, 13, 22. Bounded memory — Tasks 1, 2, 3. Opt-in — Task 13 guards. Loss-free on graceful exit — Task 15.
- CLI: `-a` / `--aggregate`, `--flowMaxAge`, mutex with `-e`/`-m` — Tasks 4, 5, 15.
- Capacity knobs section: maxFlows + maxTSvals bumps, rejection-log change — Tasks 1, 14.
- Idle reuse: covered (existing `flowMaxIdle` semantics extended via cleanUp dispatcher) — Task 7, 8.
- Row format: 9 fields, `last_tm` timestamp, `tag` field, `n_samples` resets on age-cap — Tasks 6, 8, 16.
- Summary line: `aggregated rows,` + `flows dropped (cap),` — Task 14.
- flowRec changes: 3 fields, ~16B — Task 2.
- Hot-path edits: window_start init (Task 10), n_samples increment (Task 12), FIN/RST detection (Task 11), per-match emit suppression (Task 13).
- cleanUp dispatcher: closed > idle > age-cap > no-op, plus `flush_all` for shutdown — Tasks 7, 8, 9.
- Shutdown flush — Task 15.
- Edge cases — covered by unit tests in Tasks 7–9 and integration tests in Task 21.
- Testing plan: goldens (Task 16), test_aggregate.sh (Task 17), cross-mode invariant (Task 17), age-cap synth (Task 18, 21), idle synth (Task 19, 21), shutdown-flush test (Task 15), mutual-exclusion test (Task 4), `n_samples=0` silent-delete test (Tasks 20, 21), perf check (Task 22).
- Migration: behaviour changes that affect non-`-a` users — Tasks 1, 14 implement them; README and CHANGELOG document them in Tasks 23, 24.

No spec section is uncovered.

**Type / signature consistency:** `aggregateOutput` (bool), `flowMaxAge` (double), `flowsDropped` (int), `aggregatedRows` (int), `n_samples` (uint32_t), `window_start` (double), `closed` (bool), `cleanUp(double n, bool flush_all = false)`, `emit_aggregated(const flowRec*, const FlowKey&)` — names match across all task references.

**Placeholder scan:** clean. Every step contains either runnable code, exact commands, expected outputs, or specific file/line anchors.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-06-per-flow-aggregation.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
