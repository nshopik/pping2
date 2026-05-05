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
