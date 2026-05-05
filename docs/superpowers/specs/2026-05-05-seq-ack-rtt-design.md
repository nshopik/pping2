# SEQ/ACK-based RTT measurement (hybrid TS/SEQ path)

**Status:** Approved design, ready for implementation plan
**Date:** 2026-05-05
**Owner:** Nikolay Shopik

## Problem

`pping` measures TCP round-trip time using the TCP timestamp option (TSval/TSecr).
That works on every Linux/BSD/macOS host but **not** on Windows, which does not
emit TCP timestamps by default. For workloads with mixed-OS traffic — notably
DNS-over-TCP from Windows resolvers — pping currently drops these flows
(`no_TS` counter) and produces no RTT data for them.

We add a second measurement path based on TCP sequence/acknowledgement numbers
that works on every TCP flow regardless of TSopt, and let the user choose
between the two paths via a CLI flag.

## Goals

- Recover RTT measurements on flows that lack TCP timestamps (Windows, stripped-TS middleboxes).
- Preserve the existing TS path's accuracy and behavior bit-for-bit on TS-capable flows.
- Provide a benchmarking knob so the two paths can be compared on the same workload.
- Add no global second hashmap — keep the simplification of "no second eviction loop, no second memory cap to tune."
- Keep emitted output minimal: one best-quality sample per RTT measurement, not per-segment volume that downstream ClickHouse has to deduplicate.

## Non-goals

- SACK-aware sampling.
- ICMP-based RTT correlation.
- TLS-handshake or QUIC timing.
- Per-flow RTT distributions (avg/max/stddev). The current `min`-only model is preserved.
- Output to anything but stdout.
- Flag-gated rollout. Single PR, default behavior changes (see Migration).

## High-level design

### Mode flag

A new CLI flag `--mode {ts,seq,hybrid}` (default: `hybrid`) selects the measurement
path. Internally a single enum drives all dispatch:

```cpp
enum class Mode { TS, SEQ, HYBRID };
static Mode mode = Mode::HYBRID;
```

### Per-flow classification

Each flow is classified once on its first packet through `process_packet`:

- TSopt present on first packet → `flowRec.tsCapable = true`
- TSopt absent on first packet → `flowRec.tsCapable = false`

The bit is set once and never changes for the lifetime of the flow. Mid-stream
joins use whatever the first observed packet looks like — acceptable degradation,
matches the warm-up behavior the TS path already has.

### Mode dispatch table

| Mode      | TS-capable flow            | SEQ-only flow                |
|-----------|----------------------------|------------------------------|
| `ts`      | TS path (existing)         | dropped, `no_TS++` (today)   |
| `seq`     | SEQ path (TSopt ignored)   | SEQ path                     |
| `hybrid`  | TS path (existing)         | SEQ path                     |

In `seq` mode the existing `tsTbl` receives no inserts, so it stays empty
regardless of traffic volume — the ~830MB-1.1GB worst-case `maxTSvals` cap
is moot on small hosts. In `ts` mode the SEQ-related state in `flowRec` is
unused (but the fields exist; ~25B overhead per flow regardless of mode).

### Output schema

`-e` extended output gains a 12th trailing field, always emitted regardless
of mode:

- `t` — sample produced by TS path
- `s` — sample produced by SEQ path

Existing parsers reading the first 11 fields by index keep working. Field is
appended after `node`.

`-m` (compact) format is unchanged byte-for-byte.

Human-readable format gains a trailing `[t]` or `[s]` tag at the end of each
RTT line.

### Summary stats

One new production counter and two diagnostic counters, all alongside `no_TS`:

- `seq_samples` — RTT samples emitted via SEQ path. Production-relevant: gives
  a sense of how much measurement coverage the SEQ path is providing on the
  workload. Always informative when non-zero.
- `seq_karn_drops` — samples discarded because the outstanding window was
  retransmitted (strict Karn). Diagnostic only.
- `seq_stale` — outstanding measurements aged out unmatched (parallel to
  `tsDropped`). Diagnostic only.

All three use the existing `printnz()` pattern, so diagnostic counters are
invisible in normal operation and only surface in the summary when non-zero.
No new verbosity flag needed.

In `hybrid` mode `no_TS` semantics shift from "packets dropped" to "packets
that fell through to SEQ path." Help text documents this.

## Detailed design

### Sampling strategy: one outstanding per direction

For each flow direction we track at most one in-flight RTT measurement at a
time:

- When forward data is sent, store the expected ack number (`seq + effective_len`)
  and capture time — **only if** no measurement is in flight.
- When the reverse direction's ACK ≥ stored expected ack, emit RTT and clear.
- One sample per RTT, mirroring the spirit of "first TSval wins" in the existing
  TS path.

This is strategy D from the brainstorm: one-outstanding-per-direction with
SYN/FIN handshake handled implicitly via effective-length-of-1.

### Strict Karn for retransmissions

If the outstanding window is retransmitted (any forward packet with `seq`
strictly less than `high_seq` while a measurement is in flight), set the
flow's `retx_flag`. On match, discard the sample if `retx_flag` is set.
Increment `seq_karn_drops`.

We deliberately do **not** flag `seq == high_seq` as retransmission — that's
normal in-order forward progress (next segment starts where the previous one
ended) and flagging it would invalidate the bulk of valid samples on a
sustained stream.

### Wrap-safe sequence comparison

```cpp
static inline bool seq_lt(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) < 0;
}
static inline bool seq_geq(uint32_t a, uint32_t b) noexcept {
    return int32_t(a - b) >= 0;
}
```

Used unconditionally for all seq/ack comparisons. Cost is one subtract +
signed compare; negligible on the hot path. Correct for 32-bit seq wrap on
long-lived flows.

### `flowRec` additions

```cpp
class flowRec {
    // ... existing fields unchanged ...
    uint32_t outstanding_end{0};   // expected ack; 0 = no measurement in flight
    double   outstanding_time{0.}; // capTm at store
    uint32_t high_seq{0};          // highest seq_end seen forward; for retx detection
    bool     high_seq_init{false}; // high_seq has been set (sentinel-safe across full uint32 range)
    bool     retx_flag{false};     // strict Karn: invalidate sample if set
    bool     tsCapable{false};     // classified on first packet
    bool     classified{false};    // has tsCapable been set yet
};
```

~24 bytes per flow (subject to alignment).

### `process_packet` additions

After existing TCP/IP/FlowKey parsing and `flowRec` lookup, but before the
existing TS-path code:

1. **Classify on first packet:**
   ```cpp
   if (!fr->classified) {
       fr->tsCapable = (tsopt != nullptr);
       fr->classified = true;
   }
   ```

2. **Mode dispatch:**
   - `mode == TS || (mode == HYBRID && fr->tsCapable)` → existing TS path, emit with tag `t`.
   - `mode == SEQ || (mode == HYBRID && !fr->tsCapable)` → SEQ path below, emit with tag `s`.
   - `mode == TS && !fr->tsCapable` → bump `no_TS`, return (today's behavior).

3. **SEQ path — forward state update:**
   ```cpp
   const uint32_t seq      = t_tcp->seq();
   const auto     flags    = t_tcp->flags();
   const uint32_t pay      = tcp_payload_len(pkt);
   const uint32_t eff_len  = pay
                           + ((flags & TCP::SYN) ? 1u : 0u)
                           + ((flags & TCP::FIN) ? 1u : 0u);

   if (eff_len > 0 && !toLocal) {
       const uint32_t end = seq + eff_len;
       if (!fr->high_seq_init) {
           // first forward data packet — seed retx-detection baseline
           fr->high_seq = end;
           fr->high_seq_init = true;
           fr->outstanding_end = end;
           fr->outstanding_time = capTm;
           fr->retx_flag = false;
       } else if (seq_lt(seq, fr->high_seq)) {
           // retransmission of something we've already seen
           if (fr->outstanding_end != 0) fr->retx_flag = true;
       } else {
           if (seq_geq(end, fr->high_seq)) fr->high_seq = end;
           if (fr->outstanding_end == 0) {
               fr->outstanding_end = end;
               fr->outstanding_time = capTm;
               fr->retx_flag = false;
           }
           // else: later in-flight data, don't disturb the active measurement
       }
   }
   ```

4. **SEQ path — reverse direction match:**
   ```cpp
   if (flags & TCP::ACK) {
       const uint32_t ack = t_tcp->ack_seq();
       auto rit = flows.find(rk);
       if (rit != flows.end()) {
           flowRec* rr = rit->second;
           if (rr->outstanding_end != 0 && seq_geq(ack, rr->outstanding_end)) {
               const double rtt = capTm - rr->outstanding_time;
               const bool   karn_clean = !rr->retx_flag;
               rr->outstanding_end = 0;
               rr->retx_flag = false;
               if (karn_clean) {
                   if (rr->min > rtt) rr->min = rtt;
                   ++seqSamples;
                   emit(rtt, rr, fk, /*tag=*/'s');
               } else {
                   ++seqKarnDrops;
               }
           }
       }
   }
   ```

### Output factor-out

The existing TS-path output code (lines ~439–465 of `pping.cpp`) is factored
into a shared helper:

```cpp
static void emit(double rtt, flowRec* fr, const FlowKey& fk, char tag);
```

Both paths call it with their tag char. This is the only refactor of existing
code. Cross-mode parity test (see Testing) catches any regression in the TS
path's output.

### `cleanUp()` addition

In the existing flow-eviction loop, also clear stale outstanding measurements:

```cpp
if (fr->outstanding_end != 0 &&
    capTm - fr->outstanding_time > tsvalMaxAge) {
    fr->outstanding_end = 0;
    fr->retx_flag = false;
    ++seqStale;
}
```

Same threshold as TS path's `tsvalMaxAge`. No new pass over the flow map —
folded into the existing loop.

### `filtLocal` interaction

SEQ-store is skipped on packets whose destination matches `localIPBytes`,
parallel to the existing `addTS` skip. Reverse-match always runs (it doesn't
write state, just reads).

### RST packets

RST without payload has `eff_len == 0`, so they don't touch outstanding state.
No special-case code needed.

## Testing

### Test fixtures

Three pcaps in `tests/pcaps/`, **synthesized** via a checked-in Python +
scapy script in `tests/synth/` with fixed RNG seeds for deterministic ISNs.
This lets the pcaps be regenerated on demand and swapped for real captures
later without reworking goldens — just rerun `synth/build.py`.

1. **`dns-tcp-windows.pcap`** — ~50 packets, 5 distinct flows. DNS-over-TCP
   shape (SYN, SYN+ACK, ACK, query, server-ACK, response, client-ACK, FIN,
   FIN+ACK, ACK), Windows-style TCP options (MSS + SACK-Permitted + Window
   Scale, **no** Timestamp option). Validates the headline use case. Should
   produce SEQ-path samples in `--mode hybrid` and `--mode seq`, and `no_TS`
   drops in `--mode ts`.

2. **`dns-tcp-linux.pcap`** — ~50 packets, 5 distinct flows. Same flow shape
   but with TCP Timestamp option present. Should produce identical RTT
   samples in both `--mode ts` and `--mode hybrid` (TS preempts SEQ on these
   flows). Cross-mode RTT delta should be 0.

3. **`mixed-with-retx.pcap`** — ~120 packets, 3 flows. One flow includes a
   retransmitted segment occurring while a measurement is in flight. Other
   two flows act as clean controls. Validates strict Karn drops the affected
   sample, `seq_karn_drops` increments, no spurious low/high-RTT outliers
   in output, and that minRTT for the affected flow is not polluted.

Total ~220 packets across all three pcaps; comfortable to commit, no LFS.

### Golden output

Nine golden files (`3 pcaps × 3 modes`) in `tests/golden/`. CI runs
`pping -e -r <pcap> --mode <m>` and diffs against golden. Extends the
existing `tests/golden/*` pattern.

### Cross-mode parity

`tests/cross_mode_check.sh` runs `dns-tcp-linux.pcap` through both
`--mode ts` and `--mode hybrid` and asserts emitted RTT values are
bit-identical. Catches regressions in the TS path from the `emit()`
factor-out.

### Performance benchmark

`tests/bench.sh` runs each pcap × each mode and prints `ns/pkt` + `Mpps`
(pping's existing wall-clock summary already prints these in `-r` mode).
No CI gate. Expectation: `--mode seq` marginally faster than `--mode ts` on
a Linux pcap (skips TSopt parse and `tsTbl` insert/lookup); `--mode hybrid`
matches `--mode ts` on a TS-only workload within 5%.

### Manual validation

On a real DNS-over-TCP workload, capture a same-time pcap and run all three
modes. Confirm `--mode hybrid` produces samples on flows where `--mode ts`
reports `no_TS`, and that the SEQ-path RTT distributions for a given remote
are within sanity range of same-destination ICMP RTT.

## Migration / rollout

- Single PR. No flag-gating beyond the `--mode` CLI flag itself.
- Default mode is `hybrid` — this changes default behavior for existing users:
  flows previously dropped as `no_TS` now produce SEQ-path samples.
- Output schema changes: `-e` gains a 12th field (appended); human-readable
  gains a trailing `[t]`/`[s]` tag; `-m` unchanged.
- README and help text updated in same PR.
- CHANGELOG explicitly calls out the default-mode change.
- TS path stays first-class indefinitely. SEQ path is additive. No deprecation.

## Risks

- **Output schema change for human format.** Anyone parsing human-readable
  output (which is documented as "not for parsing") gets a new trailing tag.
  Acceptable; mitigated by the `-e` and `-m` formats which are stable.
- **Default mode change surprises users.** The `no_TS` counter in `--mode hybrid`
  reports a different quantity than in `--mode ts`. Mitigated by help-text
  callout and CHANGELOG.
- **Mid-stream join misclassification.** If pping starts mid-flow on a
  TS-capable flow whose first observed packet is a pure ACK without TSopt
  (rare), the flow gets misclassified as SEQ-only. Acceptable — degrades to
  SEQ accuracy, not failure.
