# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Considered and not a finding

- `-f` BPF filter string concatenation (`pping.cpp:525`) — `-f` is from `argv` (trusted) and libpcap's filter compiler validates the result. Not exploitable.

## Bugs / robustness

- [ ] **Slow / hung Ctrl-C on idle or non-TCP links.** SIGINT can take seconds
  to stop a live capture, and hangs *forever* on a link with no filter-matching
  traffic (needs SIGKILL). Not WSL-specific — measured on bare-metal Linux
  (jade): `lo` with no TCP never exits; `ens3` exits only when the next TCP
  packet arrives (0.16–4.3s jitter); `lo` + TCP traffic exits in 0.08s. Root
  cause: `handleSignal` only sets `stopRequested`, which the packet loop checks
  at the top of each iteration — but libtins `BaseSniffer::next_packet()`
  (`sniffer.cpp:163`) blocks in `pcap_loop(handle, 1, …)` until a packet matching
  the default `tcp` filter arrives; the 250ms `set_timeout` does NOT make it
  return on an idle link. So the flag is never re-checked until the next matching
  packet (never, on a silent link). Fix: stash the handle in a global
  (`g_pcapHandle = snif->get_pcap_handle()` after sniffer creation) and call
  `pcap_breakloop(g_pcapHandle)` from `handleSignal` — `pcap_loop` then returns
  `PCAP_ERROR_BREAK`, `next_packet()` returns null, the `SnifferIterator` ends,
  and pping falls into the shutdown path (printing the new `capture:` line).
  `pcap_breakloop` only sets a flag and is the documented stop idiom (libtins'
  own `stop_sniff()` uses it), so it's safe from the handler — add an
  async-signal-safety comment like the existing SIGHUP one. Own branch/PR;
  security-relevant signal-handler change.

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
