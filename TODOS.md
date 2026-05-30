# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Considered and not a finding

- `-f` BPF filter string concatenation (`pping.cpp:525`) — `-f` is from `argv` (trusted) and libpcap's filter compiler validates the result. Not exploitable.

## SEQ/ACK feature follow-ups

Surfaced in the final review of the `seq-ack-rtt` branch. None block merge.

- [ ] **Add IPv6 + SEQ test coverage.** All three pcap fixtures (`dns-tcp-linux.pcap`, `dns-tcp-windows.pcap`, `mixed-with-retx.pcap`) are IPv4. The SEQ-path code is address-family agnostic but no end-to-end golden exercises v6 + SEQ. Add a `dns-tcp6-windows.pcap` fixture and goldens for `--mode seq` and `--mode hybrid`.

- [ ] **`bytesDep` is always 0 in SEQ-emitted samples.** The TS path writes `bytesDep` on the reverse flow when emitting; the SEQ path reads `rr->bytesDep` but never writes it. In `--mode seq` runs `dBytes` is always 0; in `--mode hybrid` on a mixed pcap the field is asymmetric between `t`-tagged and `s`-tagged samples. Either mirror the TS path's bookkeeping in the SEQ match block, or document the asymmetry.

- [ ] **Extend `cross_mode_check.sh` to assert `--mode seq == --mode hybrid` on `dns-tcp-windows.pcap`.** The current script only asserts `--mode ts == --mode hybrid` on a TS-capable pcap. The dual property is implicit from the goldens but not asserted; locking it in is a 5-line addition.

## Future features

- [ ] **Flow-age column in per-sample modes.** The 2026-05-13 flow-duration export added `flow_start` to aggregate-mode rows only. The per-sample equivalent is "flow age at sample time" (`capTm - window_start`), resetting on `flowMaxAge` — not lifetime. Every row gains a column, so downstream schema/loader churn is much larger than the aggregate-mode change. Wait for a concrete query pattern that needs it.

- [ ] **Multi-interface support with per-row `interface` column.** Accept multiple `-i` flags (or comma-separated list), tag each row with the interface name, ship a templated systemd unit (`pping@.service`). Schema gains `interface LowCardinality(String)`; `pping_flows` ORDER BY may want to lead with `interface` for tenant-style queries.

## Performance follow-ups

Deferred from the 2026-05-30 Dream Team performance review (`cpp-pro` +
`performance-engineer`). The three cheap wins from that review already landed
(ring-buffer sizing, `addTS` cap-path single-lookup, `make pgo` target). The
items below need a **1M+ pcap with realistic flow churn** before acting —
≤200K fixtures hide hashmap and libtins cost, so any number from them is noise.

- [ ] **`cleanUp()` is an O(N) stop-the-world scan.** `pping.cpp:710` walks all
  of `tsTbl` (≤33.5M) and `flows` (≤67M) every `tsvalMaxAge` (10s). At cap that
  touches gigabytes of node-based heap in one pass — during live capture the
  packet loop is paused for the whole scan, and the kernel ring (now 16MB) drains
  meanwhile. Candidate redesign: time-bucketed ring of maps, evict the oldest
  bucket wholesale per tick (O(N/window) instead of O(N)). **Profile first:**
  instrument `clock_gettime()` around the `cleanUp()` call on a 1M+ pcap; only
  act if it's >5% of wall time.

- [ ] **`reserve()` both maps at startup — to a realistic estimate, NOT the cap.**
  Reserving to `maxFlows`/`maxTSvals` would commit ~14GB up front (the review
  agents both missed this). Reserve to expected concurrent flow count (low
  millions) to skip early-growth rehash spikes without the memory blowup.

- [ ] **`pkt.pdu()->size()` virtual PDU-tree walk.** `pping.cpp:581` recurses
  the libtins PDU chain (virtual call per layer) for a byte count obtainable as
  `14 + ntohs(ip->tot_len())` (v4) / `14 + 40 + ntohs(ipv6->payload_length())`
  (v6). Mechanical change; small relative to hashmap cost. Confirm byte-count
  semantics match the goldens (`-e`/`-a` byte fields).

- [ ] **`fmtTimeDiff()` returns `std::string` (2 heap allocs/sample).**
  `pping.cpp:357`, called from `emit()` human path only. Apply the `IpStr`
  pattern (stack `char[]` struct returned by value). **Low value for the
  production `-a` → ClickHouse pipeline:** `-a` sets `aggregateOutput`, which
  gates out `emit()` entirely, so `fmtTimeDiff` never runs there. Only matters
  for interactive human-mode output.

- [ ] **`flowRec` layout: 7B internal pad, hot fields span 3 cache lines.**
  `pping.cpp:184-228`. Reorder (doubles → pointer → uint32 → bools) to ~88B and
  pull `tsCapable`/`classified` (read every packet at `pping.cpp:547`) into the
  first cache line. Add a `static_assert` on `sizeof(flowRec)` after. Marginal
  unless the working set pressures L1/L2 — **cachegrind first.**

- [ ] **Per-flow `new`/`delete` churn.** `pping.cpp:524`/`756`. A `flowRec`
  freelist pool would eliminate malloc traffic, but only worth it if new-flow
  rate exceeds ~5% of pps (check `flowCnt` vs `pktCnt` in the summary). Measure
  before building.

## Install / packaging follow-ups

- [ ] **Tests for `--logfile` and SIGHUP reopen.** `test/test_cli.sh` doesn't cover the new flag. Add a check that `pping --logfile=/tmp/x.log -r test/pcaps/known.pcap` writes output to that path and produces the same content as plain stdout redirection. SIGHUP/rotation behavior is harder to test without live capture but a fork+kill+inode-comparison contrived test would work.
