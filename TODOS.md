# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Security-adjacent (hostile-input hardening)

- [ ] **Wrap libtins calls that take untrusted bytes.** `pkt.pdu()->find_pdu<TCP>()`, `find_pdu<IP>()`, and the `src_addr()` paths can throw or return null on malformed packets. Only `timestamp()` is wrapped today. Add a top-level `try { ... } catch (std::exception&) { return; }` around the parse section in `process_packet`, and check `pkt.pdu()` for null first.

## Robustness (local crashes, not security)

- [ ] **Null-check `ifa_addr` in `localAddrOf`.** `getifaddrs(3)` is allowed to return entries with `ifa_addr == NULL` (e.g. some virtual interfaces). Skip those instead of dereferencing. `pping.cpp:416`.

- [ ] **Null-check `info->ai_canonname` in `getFQDN`.** `getaddrinfo` does not guarantee `ai_canonname` is set even with `AI_CANONNAME` requested. Fall back to `hostname` if null. `pping.cpp:399`.

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

- [ ] **Validate `PREFIX` / `SYSCONFDIR` in install recipes.** Currently `make install-systemd SYSCONFDIR=` (empty) silently creates `/default/pping`; `PREFIX=/usr/local/bin/foo|bar` (containing the sed delimiter `|`) corrupts the substituted scripts without failing. Add early `@test -n "$(PREFIX)"` / `@test -n "$(SYSCONFDIR)"` guards to `install-*` targets. For sed-metachar safety either escape the substitution value or document the constraint in the Makefile comments. `Makefile:42-44`.

- [ ] **Handle `DESTDIR` whitespace robustly.** `if [ -z "$(DESTDIR)" ]` treats `DESTDIR=" "` (single space, common shell typo) as set — silently skips `setcap` and the install warning, leaving an unprivileged binary with no diagnostic. Either trim before checking, or document that `DESTDIR` must be empty rather than whitespace-only. `Makefile:47-58`.
