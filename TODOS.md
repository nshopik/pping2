# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Security-adjacent (hostile-input hardening)

- [ ] **Wrap libtins calls that take untrusted bytes.** `pkt.pdu()->find_pdu<TCP>()`, `find_pdu<IP>()`, and the `src_addr()` paths can throw or return null on malformed packets. Only `timestamp()` is wrapped today. Add a top-level `try { ... } catch (std::exception&) { return; }` around the parse section in `process_packet`, and check `pkt.pdu()` for null first.

## Considered and not a finding

- `-f` BPF filter string concatenation (`pping.cpp:525`) — `-f` is from `argv` (trusted) and libpcap's filter compiler validates the result. Not exploitable.

## SEQ/ACK feature follow-ups

Surfaced in the final review of the `seq-ack-rtt` branch. None block merge.

- [ ] **Add IPv6 + SEQ test coverage.** All three pcap fixtures (`dns-tcp-linux.pcap`, `dns-tcp-windows.pcap`, `mixed-with-retx.pcap`) are IPv4. The SEQ-path code is address-family agnostic but no end-to-end golden exercises v6 + SEQ. Add a `dns-tcp6-windows.pcap` fixture and goldens for `--mode seq` and `--mode hybrid`.

- [ ] **`bytesDep` is always 0 in SEQ-emitted samples.** The TS path writes `bytesDep` on the reverse flow when emitting; the SEQ path reads `rr->bytesDep` but never writes it. In `--mode seq` runs `dBytes` is always 0; in `--mode hybrid` on a mixed pcap the field is asymmetric between `t`-tagged and `s`-tagged samples. Either mirror the TS path's bookkeeping in the SEQ match block, or document the asymmetry.

- [ ] **Extend `cross_mode_check.sh` to assert `--mode seq == --mode hybrid` on `dns-tcp-windows.pcap`.** The current script only asserts `--mode ts == --mode hybrid` on a TS-capable pcap. The dual property is implicit from the goldens but not asserted; locking it in is a 5-line addition.

- [ ] **Document the golden regeneration runbook.** The procedure (`make pcaps`, then per-pcap-per-mode `pping -e --mode <m> -r ... | awk '{$11=""; ...}'`) is captured implicitly across `test/test_seq.sh`, `test/synth/`, and `Makefile`. A short comment block at the top of `test_seq.sh` or a `## Regenerating goldens` section in README would help future maintainers.

## Future features

- [ ] **Multi-interface support with per-row `interface` column.** Today
  each pping instance monitors a single interface; running multiple
  capture points on one host means multiple manually-managed unit
  instances. Proper support means accepting multiple `-i` flags (or a
  comma-separated list), tagging each emitted row with the interface
  name, and shipping a templated systemd unit (`pping@.service`) so
  operators can `systemctl enable pping@eth0 pping@eth1`. Schema gains
  an `interface LowCardinality(String)` column; `pping_flows` ORDER BY
  may want to lead with `interface` for tenant-style queries.

## Install / packaging follow-ups

Surfaced in the Opus adversarial review of the `install-quickstart` branch. None block merge; all are low-priority polish.

- [ ] **CI: smoke-test the install targets.** Add a `make install-all DESTDIR=$(mktemp -d) PREFIX=/usr SYSCONFDIR=/etc` step to `.github/workflows/` after the build. Assert all 6 expected files appear at expected paths. Catches Makefile recipe regressions, sed-substitution correctness, and unit-file syntax (optionally pipe through `systemd-analyze verify`). Today these targets aren't exercised in CI — only manual WSL smoke tests.

- [ ] **Tests for `--logfile` and SIGHUP reopen.** `test/test_cli.sh` doesn't cover the new flag. Add a check that `pping --logfile=/tmp/x.log -r test/pcaps/known.pcap` writes output to that path and produces the same content as plain stdout redirection. SIGHUP/rotation behavior is harder to test without live capture but a fork+kill+inode-comparison contrived test would work.

## Performance follow-ups (phase 3)

If/when someone wants another perf swing, the spec's *Out of scope* section already names the unused levers, ranked by effort vs expected payoff:

- [ ] **Parallel-stream CRC32.** Two/three independent accumulators to break the 3-cycle `crc32q` dependency chain. ~15 LOC on top of `CRC32Hash`. Marginal — maybe 1–2% on top of phase-2 since hashing is no longer the top cluster.
- [ ] **v4 key shrink.** When `af == 4`, hash only the meaningful 24 bytes (4 src + 4 dst + 2 sport + 2 dport + pad) instead of the full 40. Touches `FlowKey::operator==` and `reversed()`. ~80 LOC + test updates. Cuts hash work ~40% on v4-dominant traffic; bigger payoff but bigger refactor.
- [ ] **CRC32 + robin_map combined.** The phase-2 robin_map work proved structural alone is not enough, but the vendored headers are gone now; revisiting this lever means re-vendoring tsl or trying `phmap::flat_hash_map`. Only interesting if profile dominance shifts back to map probe cost.
- [ ] **Integer-microseconds timekeeping.** Replace `double` capTm with `int64_t` microseconds; saves the implicit double→int conversions on every match. Touches more of the code than it sounds.

Plus the failure-note's brainstorm seeds (alternative hash families: xxhash3, absl::Hash, phmap) — only relevant if CRC32C distribution quality ever shows up as a bottleneck, which it currently does not.
