# TODOs

Items deferred from the `/cso` security audit. Most are DoS / robustness, not directly exploitable, but worth fixing if pping is used to process untrusted pcap files or capture from a wire that hostile traffic can reach.

## Security-adjacent (hostile-input hardening)

- [ ] **Bound `tsTbl` size.** `flows` is capped at `maxFlows` (65535), but `tsTbl` has no analogous cap. `cleanUp()` only prunes every `tsvalMaxAge` seconds (default 10s), so a flooder can grow `tsTbl` arbitrarily within each window. Add a hard cap (e.g. 4× `maxFlows`) and either drop new entries or evict oldest when full. `pping.cpp:119, 311-312`.

- [ ] **Fix `tsInfo*` leak on duplicate-key insert.** `addTS()` does not store or delete the passed pointer when the key already exists; the caller unconditionally `new`s a `tsInfo`. Either move the allocation inside `addTS()` (only allocate after the existence check) or have `addTS()` `delete` the duplicate. `pping.cpp:152-161`, caller at `311-312`.

- [ ] **Wrap libtins calls that take untrusted bytes.** `pkt.pdu()->find_pdu<TCP>()`, `find_pdu<IP>()`, and the `src_addr().to_string()` paths can throw or return null on malformed packets. Only `timestamp()` is wrapped today. Add a top-level `try { ... } catch (std::exception&) { return; }` around the parse section in `process_packet`, and check `pkt.pdu()` for null first. `pping.cpp:231, 249-254`.

## Robustness (local crashes, not security)

- [ ] **Null-check `ifa_addr` in `localAddrOf`.** `getifaddrs(3)` is allowed to return entries with `ifa_addr == NULL` (e.g. some virtual interfaces). Skip those instead of dereferencing. `pping.cpp:416`.

- [ ] **Null-check `info->ai_canonname` in `getFQDN`.** `getaddrinfo` does not guarantee `ai_canonname` is set even with `AI_CANONNAME` requested. Fall back to `hostname` if null. `pping.cpp:399`.

## Considered and not a finding

- `-f` BPF filter string concatenation (`pping.cpp:525`) — `-f` is from `argv` (trusted) and libpcap's filter compiler validates the result. Not exploitable.
