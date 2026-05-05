# Per-flow RTT aggregation (`-a` mode)

**Status:** design
**Date:** 2026-05-06
**Branch:** `flow-aggregate`

## Problem

pping today emits one line per RTT match (one per TS echo match, one per
SEQ-closing ACK). For a busy capture point this produces high-volume,
low-density output that the downstream ClickHouse pipeline immediately
aggregates by reducing to per-flow `min` (then network-aggregating to
/24 IPv4 / /48 IPv6 buckets). The TS- and SEQ-match printf is also the
single most expensive operation on pping's hot path.

We want to do that first reduction at the capture point: one row per flow
per window instead of one row per RTT sample. This trades a small per-flow
memory footprint for substantially fewer output bytes, less ClickHouse
ingest cost, and lower per-packet CPU on the pping side (we delete the
per-match printf).

## Goals

- Emit at most one row per flow per closure event or per `flowMaxAge`
  window, instead of one row per RTT sample.
- Carry only the fields ClickHouse actually consumes: per-flow `min` RTT
  plus identifiers and a sample count for downstream confidence filtering.
- Strictly cheaper per-packet than today's per-match emit.
- Bounded memory: per-flow accumulator stays small relative to the
  flowRec it lives in (~16 B added on top of ~80 B). The flow-table
  cap is also being raised in this change (see Capacity knobs below)
  so accumulator memory scales with the new `maxFlows` ceiling.
- Opt-in: today's `-e`, `-m`, and human-readable outputs continue
  bit-for-bit unchanged.
- Loss-free on graceful exit: in-progress flows flush their rows on
  SIGINT, SIGTERM, end-of-pcap, `-c N`, or `-s N`.

## Non-goals

- Per-flow `max`, `avg`, `sum`, percentiles, or any sketch-based metric.
  ClickHouse only consumes `min`; everything else is dead weight.
- Per-flow byte counters (`fBytes`, `dBytes`, `pBytes`) on the aggregated
  row. Not consumed downstream. Existing flowRec byte tracking stays for
  internal use; it just isn't emitted.
- Wall-clock-aligned cap windows (e.g., "always emit at the top of the
  hour"). Per-flow age cap is sufficient and avoids the synchronized-emit
  spike that wall-clock alignment would create across all flows at once.
- Asynchronous emission (worker thread, queue). Overengineering for
  pping's single-threaded model.
- Replacing or deprecating `-e`. It stays available indefinitely.

## User-facing surface

### CLI flag

`-a` / `--aggregate`. Enables aggregator output mode. Mutually exclusive
with `-e` and `-m`; combining them is a startup error:

```
fatal: -a/--aggregate is mutually exclusive with -e/--extended and -m/--machine
```

### Cap knob

`--flowMaxAge=<seconds>`. Default `1800` (30 minutes — middle ground
between the typical 1H ClickHouse dashboard granularity and the 15m
investigation granularity). Range `[0, ∞)`. `0` disables the age
cap entirely (rely on FIN/RST/idle for emission). Negative values are
rejected at startup. No upper ceiling — operators who want very long
windows already have `0=disabled` as the bigger footgun, so an
intermediate ceiling adds no real protection.

### Capacity knobs

The aggregation feature stores per-flow accumulator state, so the
existing flow-table cap matters more in practice. Two related changes:

- **`maxFlows` default raised to `1,048,576` (`1024^2`, 1M binary)**
  from the prior `65535`. Justification: pping's single-thread
  capture ceiling is in the 2–3 Mpps range on a modern core; even
  in a hostile profile where every second packet opens a new flow,
  1M concurrent flows is well past the realistic worst case. Memory
  at full cap: ~96 B per flowRec × 1M plus unordered_map overhead
  ≈ ~170 MB total. Trivial on any host that runs ClickHouse-adjacent
  tooling.

- **`--maxFlows=N` CLI knob.** Range `[1024, ∞)`. `0 = unlimited`
  (relies on host memory and the natural age-out via `flowMaxIdle`
  to bound growth — same convention as `flowMaxAge=0`). Values below
  1024 are rejected at startup; otherwise unbounded.

- **`maxTSvals` default raised to `268,435,456` (`16^7` = `2^28`,
  256M binary).** The prior `4,000,000` was sized for 100–200 K pps;
  at 1 Mpps and beyond it becomes the constraint. Worst-case memory
  at the new cap (using the per-entry cost recorded in the existing
  `pping.cpp` comment of ~207 B IPv4 / ~275 B IPv6): ~56 GB IPv4 /
  ~74 GB IPv6. That's the theoretical ceiling — realistic steady-state
  at 1 Mpps stays in the single-digit GB range, gated by `tsvalMaxAge`
  (10s default) × TSval-tick-rate × concurrent TS-capable flow count.
  No CLI knob; just a default bump.

- **Rejection log rate-limited.** The existing per-rejection
  `std::cerr` line in `process_packet` (around line 422) is removed.
  Replaced by a counter `flowsDropped` that increments on each
  rejection and is printed in `printSummary()` as
  `<n> flows dropped (cap),` when non-zero. Per-rejection logging at
  high pps would otherwise fill stderr with thousands of lines/sec.

### Idle reuse

`--flowMaxIdle` (existing flag, default 300s) is reused unchanged. A
flowRec is "idle" when `capTm - fr->last_tm > flowMaxIdle`. Today this
silently deletes the flowRec; under `-a` it emits a row first if
`n_samples > 0`, then deletes.

### Row format

Nine fields, space-separated, no quoting. Same epoch.usec timestamp
format as `-e`. RTT in seconds with 6-digit precision.

```
epoch.usec min_rtt n_samples srcIP sport dstIP dport node tag
```

Example:

```
1715876442.123456 0.008700 247 192.168.1.5 54321 34.107.221.82 443 host.example.com t
```

Field semantics:

- `epoch.usec`: the flow's stored `last_tm` at emission — the time of the
  last packet seen on this direction's flowRec. Crucially **not** the
  cleanUp tick time, which would introduce up to ~10s of timestamp noise.
- `min_rtt`: minimum RTT observed in this row's window, in seconds.
- `n_samples`: count of RTT matches contributing to `min_rtt` for this
  window only (resets on age-cap fire). Useful for downstream confidence
  filters: a `min` derived from a single RTT match is statistically noisy.
- `srcIP sport dstIP dport`: 5-tuple identifying the flow direction.
- `node`: capture host's FQDN, as in `-e`.
- `tag`: `t` for TS-capable flows, `s` for SEQ-only flows. Constant per
  flow (set on first packet via `tsCapable`, never changes), so constant
  per row of any window of that flow. Carried forward for diagnostic
  parity with `-e`.

### Summary line

`printSummary()` gains one new counter, printed when non-zero:
`<n> aggregated rows,`. Reset each summary interval like the existing
counters.

## Implementation

### flowRec changes

Three new fields on `flowRec` (in `pping.cpp`, around line 156):

```cpp
uint32_t n_samples   = 0;       // RTT matches in current window
double   window_start = 0.;     // capTm at flow creation; reset on age-cap fire
bool     closed       = false;  // first FIN seen on this dir, or RST seen
                                // on either dir (peer flag set via revFlowRec)
```

Total ~16 bytes after struct padding. At the new `maxFlows = 1,048,576`
(`1024^2`, 1M) default cap, the accumulator portion adds ~16 MB on
top of the existing flowRec footprint (~96 B per flow × 1M ≈ 96 MB
total flowRec heap, plus unordered_map node overhead bringing the
combined total to ~170 MB). Well within budget for any host that
runs ClickHouse-adjacent tooling.

### Hot-path edits in `process_packet`

Three additions, all O(1) per packet:

1. **On flow creation** (the `inserted` branch around line 420):
   `fr->window_start = capTm;`
   One additional store.

2. **On TS match** (line ~507): `++fr->n_samples` immediately after the
   existing `if (fr->min > rtt) fr->min = rtt;`. The TS-path credits
   `fr` (this packet's flowRec — the direction whose ECR matched a
   stored TSval), matching where `min` is updated today.
   **On SEQ match** (line ~573, in the `karn_clean` branch):
   `++rr->n_samples` immediately after `if (rr->min > rtt) rr->min = rtt;`.
   The SEQ-path credits `rr` (the reverse-of-this-packet flowRec — the
   direction whose data was acknowledged), again matching the existing
   `min`-update target. One additional integer increment per match in
   each branch; no new control-flow branches.

3. **On FIN/RST observation**, before the existing TS/SEQ dispatch
   (after `revFlow` is verified at line ~465):

   ```cpp
   const auto flags = t_tcp->flags();
   if (flags & TCP::FIN) {
       fr->closed = true;
   }
   if (flags & TCP::RST) {
       fr->closed = true;
       if (fr->revFlowRec) fr->revFlowRec->closed = true;
   }
   ```

   FIN is unidirectional in TCP — A's FIN means A→B is winding down,
   but B may still send. So FIN sets `closed` only on this direction's
   flowRec. RST is bidirectional: both endpoints treat the connection as
   dead, so we propagate via `revFlowRec` (null-checked, since the peer
   may have been idle-evicted earlier).

   Cost: two cheap branches and at most two byte stores. No new
   allocations, no map lookups, no printf.

**Per-match emit suppression:** when aggregator mode is active, the
TS-path `emit(...)` call (line ~521) and the SEQ-path `emit(...)` call
(line ~583) are guarded by a runtime check on the new mode flag. Don't
introduce a separate code path; the per-match `min` and `n_samples`
updates still happen — only the printf is skipped.

### `cleanUp` becomes the single emit site

cleanUp's loop body becomes a four-priority dispatcher per flowRec:

```
if (fr->closed)
    → if (n_samples > 0) emit_row(); delete flowRec  (priority 1)
else if (capTm - fr->last_tm > flowMaxIdle)
    → if (n_samples > 0) emit_row(); delete flowRec  (priority 2)
else if (flowMaxAge > 0 && capTm - fr->window_start > flowMaxAge)
    → if (n_samples > 0) emit_row();
      reset_window(fr);                              (priority 3)
else
    → leave alone                                   (priority 4)
```

`reset_window(fr)` zeros `n_samples`, sets `min = 1e30`, sets
`window_start = capTm`, sets `lstBytesSnt = bytesSnt`. **TCP state
is preserved** (`high_seq`, `high_seq_init`, `outstanding_end`,
`outstanding_time`, `retx_flag`, `revFlowRec`, `bytesSnt`, `bytesDep`,
`tsCapable`, `classified`, `last_tm`). SEQ tracking continues seamlessly
into the next window.

`n_samples == 0` flowRecs (one-direction-only flows that never produced
a measurement — e.g. failed SYNs, scans, half-direction bursts) are
**silently deleted on idle** without emitting. Avoids ClickHouse rows
that contain no useful data.

The age-cap branch does not invalidate the iterator (no `erase`).

### Shutdown flush

The existing exit paths — SIGINT/SIGTERM signal handler, end of pcap
sniffer iteration, `-c maxPackets` cap, `-s time_to_run` cap — all
funnel through `main()`'s post-loop block. Add one final cleanUp call
there with all-flows-emit semantics: every flowRec with `n_samples > 0`
emits a row using its own `last_tm`, regardless of trigger. Then
delete all entries.

This guarantees no in-progress accumulator data is silently dropped on
graceful exit. (Crash-loss is still possible — the design does not
attempt persistence across pping process restarts.)

### Output emission helper

Add `emit_aggregated(fr, fk)` adjacent to existing `emit()`. Same printf
flush cadence as `emit()`. Format:

```cpp
printf("%" PRId64 ".%06d %.6f %u %s %u %s %u %s %c\n",
       int64_t(fr->last_tm + offTm),
       int((fr->last_tm - floor(fr->last_tm)) * 1e6),
       fr->min, fr->n_samples,
       ipsstr.c_str(), fk.sport,
       ipdstr.c_str(), fk.dport,
       node.c_str(),
       fr->tsCapable ? 't' : 's');
```

## CPU and memory analysis

**Per-packet hot path:** strictly cheaper than today on average. We add
~3 always-on operations (FIN/RST flag check, n_samples increment on
match, window_start store on flow creation). We remove one `printf`
per RTT match plus the periodic `fflush` it triggers. printf is
expensive (format string interpretation, lock acquisition, syscall
batching); a `++` on a uint32 is sub-nanosecond. Net delta is negative
for any flow that produces ≥1 RTT sample (i.e. all interesting flows).

Verifiable via the existing `wall-clock` benchmark line in `-r` mode:
re-run on `mixed-with-retx.pcap` with and without `-a` and confirm
`ns/pkt` does not regress. The acceptance bar is *no regression* under
default `-r` mode (per-match emit), and *improvement* under `-r -a`.

**Memory:** per-flow accumulator grows by ~16 bytes. At the new
`maxFlows = 1,048,576` (`1024^2`, 1M) default cap, accumulator
memory adds ~16 MB on top of the existing flowRec footprint
(~96 B × 1M ≈ 96 MB total flowRec heap, ~170 MB combined with
unordered_map overhead). Operators who set `--maxFlows=0` (unlimited)
or a higher explicit value will scale memory linearly. Adjacent
`maxTSvals` is raised to `268,435,456` (`16^7`, 256M binary);
worst-case at the cap is ~56 GB IPv4 / ~74 GB IPv6, but realistic
steady-state at 1 Mpps with `tsvalMaxAge=10s` stays in single-digit GB.

**Output volume:** for a typical workload with ~20 RTT samples per flow,
`-a` produces ~5% of the row count of `-e`. Exact ratio depends on
flow length distribution.

## Edge cases

- **Half-direction flows** (one-way SYN, scan, port-knock): silent
  delete on idle — no useless rows in ClickHouse.
- **Karn drops**: increment `seqKarnDrops` as today; do *not* increment
  `n_samples`. Per-flow `min` reflects only Karn-clean RTTs, matching
  existing semantics.
- **Half-closed flows** (one direction sent FIN, the other still active):
  the FINned direction's flowRec emits and is deleted; the still-active
  direction continues collecting until its own FIN, RST, or idle.
- **Reverse-flow eviction race**: if peer flowRec was idle-evicted before
  RST arrives, `revFlowRec` is null. The null-check in the RST-propagation
  branch makes this a no-op for the (already-evicted) peer. Same pattern
  as the existing SEQ-path null check.
- **Age-cap fire timing**: cleanUp runs every `tsvalMaxAge` (10s default)
  ticks of capture time. So in the worst case a flow's age-cap row emits
  up to 10s after the cap technically expired. Because the row's timestamp
  uses `last_tm` (not the cleanUp-tick time), the row's claimed time is
  still accurate to the last packet seen.
- **Multi-row long flow**: a long flow with `n_samples > 0` in each
  window produces N rows in ClickHouse with the same 5-tuple, distinct
  `last_tm`. Window boundaries are implicit (gap between rows of the
  same 5-tuple). If you ever need explicit window start times, add
  `first_tm` as a 10th field — additive, not breaking.
- **maxFlows pressure**: cap raised to 1M default with `--maxFlows`
  knob (see Capacity knobs). New flows still silently rejected when
  full; the prior per-rejection stderr line is replaced by a counter
  reported in the summary line. Existing aggregating flows continue
  normally regardless of cap pressure.
- **`flowMaxAge=0`** disables the age cap entirely. Long flows then
  flush only on FIN/RST/idle/shutdown. Memory still bounded by `maxFlows`,
  so safe; the trade-off is data freshness on truly long-lived flows.
- **`maxFlows=0`** means unlimited — host memory and `flowMaxIdle`
  natural age-out become the only bounds. Appropriate for hosts with
  generous memory and traffic profiles that don't churn aggressively.

## Testing

### Golden files

Three new fixtures, one per existing pcap:

- `test/dns-tcp-linux-aggregate.golden`
- `test/dns-tcp-windows-aggregate.golden`
- `test/mixed-with-retx-aggregate.golden`

Generated by `pping -a -r <fixture> | sort` (sort because cleanUp
ordering is not packet-deterministic across libstdc++ versions —
`unordered_map` iteration order is implementation-defined). Comparison
uses sorted output too. Wired into `make test` and `test/test_seq.sh`
alongside existing goldens.

### Cross-mode invariant

In `test/cross_mode_check.sh`, add: for any pcap, `sum(n_samples)` in
`-a` output equals row count in `-e` output, for the same pcap and
mode. One-line awk assertion. Locks in "no samples lost or
double-counted" without depending on cleanUp timing.

### Synthetic age-cap test

A small generated pcap (`test/synth/age_cap.pcap`) with packets spanning
~12 seconds of capture-time on a single long flow. Test invocation:

```sh
pping -a --flowMaxAge=5 -r test/synth/age_cap.pcap | sort
```

Asserts ≥2 rows for the synthesized 5-tuple (the cap fires at least
twice during the synthetic window). Wall-clock runtime is milliseconds
because pcap replay is CPU-bound; the small `--flowMaxAge` value is
what makes the test fast despite testing the cap behavior.

### Idle-emit test

Generate a small pcap (`test/synth/idle.pcap`) where a flow goes silent
mid-replay with later traffic on a different flow. Run with
`pping -a --flowMaxIdle=2 -r ...`. Assert the silent flow emits a row
whose timestamp equals the last packet's `last_tm`, **not** the
cleanUp-tick time.

### Shutdown flush test

Run `pping -a -c 50 -r <fixture>` against a fixture with a known live
flow count at packet 50. Assert that every live flow at the cut point
emits exactly one row.

### Mutual-exclusion test

`pping -a -e -r foo.pcap` exits non-zero with the expected stderr
message. One-liner shell assertion.

### `n_samples == 0` silent-delete test

A pcap of a single SYN with no SYN-ACK reply. Assert zero output rows
from `-a`, even after idle expiry. Generated inline with a small
fixture committed to `test/synth/`.

### Performance regression check

Run the existing benchmark line on `mixed-with-retx.pcap` in three
configurations: default (`-r`), `-r -e`, `-r -a`. Acceptance:

- `-r -a` ns/pkt ≤ `-r -e` ns/pkt (printf elimination dominates).
- `-r -e` ns/pkt unchanged from main (we did not touch the existing
  per-match path beyond mode-guarding the printf).

## Migration

- No row-format change for users not passing `-a`. The 9 existing
  SEQ/ACK golden files (3 fixtures × 3 modes) remain byte-identical.
- ClickHouse ingest pipeline switches to `pping -a ...` whenever the
  operator decides to. Schema changes required: drop `fBytes`, `dBytes`,
  `pBytes` from the ingest table, add `n_samples`. Both old and new
  pping versions can run side-by-side during rollout.
- `-e` remains available for diagnostic / live-debug use indefinitely.
- **Behavior changes that affect *all* users** (regardless of `-a`):
  - `maxFlows` default rises from 65535 to 1,048,576 (`1024^2`, 1M).
    Steady-state memory grows proportionally on hosts whose live flow
    count was previously saturating the old cap. Operators on
    memory-constrained hosts can pin to the old default with
    `--maxFlows=65535`.
  - `maxTSvals` default rises from 4M to 256M (`16^7` = `2^28` =
    268,435,456). Hosts that were hitting `tsTbl drops` will see
    those go away; memory bounded instead by `tsvalMaxAge` and host
    RAM. Worst-case memory at the new cap: ~56 GB IPv4 / ~74 GB IPv6
    (theoretical ceiling; real workloads at 1 Mpps stay in single-
    digit GB).
  - Per-rejection `flow limit (...) reached, dropping new flow: ...`
    stderr line is removed in favor of the summary-line counter.
    Operators relying on the old line for monitoring need to switch
    to parsing the summary `<n> flows dropped (cap),` field.

## Open questions

None blocking. Optional follow-up:

- Add `first_tm` as a 10th row field if explicit per-window start times
  prove useful for ClickHouse multi-row flow correlation. Additive.
- Add `tsCapable` filter to ClickHouse rollup queries if TS-vs-SEQ
  measurement bias proves material. The `tag` field already supports this.
