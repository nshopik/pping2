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

## Install / packaging follow-ups

- [ ] **Tests for `--logfile` and SIGHUP reopen.** `test/test_cli.sh` doesn't cover the new flag. Add a check that `pping --logfile=/tmp/x.log -r test/pcaps/known.pcap` writes output to that path and produces the same content as plain stdout redirection. SIGHUP/rotation behavior is harder to test without live capture but a fork+kill+inode-comparison contrived test would work.
