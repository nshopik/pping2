# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Security-adjacent (hostile-input hardening)

- [ ] **Wrap libtins calls that take untrusted bytes.** `pkt.pdu()->find_pdu<TCP>()`, `find_pdu<IP>()`, and the `src_addr()` paths can throw or return null on malformed packets. Only `timestamp()` is wrapped today. Add a top-level `try { ... } catch (std::exception&) { return; }` around the parse section in `process_packet`, and check `pkt.pdu()` for null first.

## Robustness (local crashes, not security)

- [ ] **Null-check `ifa_addr` in `localAddrOf`.** `getifaddrs(3)` is allowed to return entries with `ifa_addr == NULL` (e.g. some virtual interfaces). Skip those instead of dereferencing. `pping.cpp:416`.

- [ ] **Null-check `info->ai_canonname` in `getFQDN`.** `getaddrinfo` does not guarantee `ai_canonname` is set even with `AI_CANONNAME` requested. Fall back to `hostname` if null. `pping.cpp:399`.

## Considered and not a finding

- `-f` BPF filter string concatenation (`pping.cpp:525`) — `-f` is from `argv` (trusted) and libpcap's filter compiler validates the result. Not exploitable.
