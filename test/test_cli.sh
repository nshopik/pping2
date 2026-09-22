#!/bin/sh
# test_cli.sh — CLI surface tests for the aggregator flags.
# POSIX sh.
. "$(dirname "$0")/lib.sh"

PCAP="$PCAPS_DIR/known.pcap"

# 1. -a -e is rejected at startup
ERR=$("$PPING" -a -e -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_e_mutex"
else
    fail "a_e_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 2. -a -m is rejected at startup
ERR=$("$PPING" -a -m -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_m_mutex"
else
    fail "a_m_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 3. --flowMaxAge=0 (disable) accepted
if "$PPING" -a --flowMaxAge=0 -r "$PCAP" >/dev/null 2>&1; then
    pass "flowMaxAge_zero"
else
    fail "flowMaxAge_zero" "exit non-zero"
fi

# 4. --flowMaxAge=-1 rejected
ERR=$("$PPING" -a --flowMaxAge=-1 -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "flowMaxAge"; then
    pass "flowMaxAge_negative_rejected"
else
    fail "flowMaxAge_negative_rejected" "expected non-zero exit + flowMaxAge in stderr; got rc=$RC"
fi

# 5. -h/--help mentions -a and --flowMaxAge
HELP=$("$PPING" --help 2>&1)
if echo "$HELP" | grep -q "\-a|--aggregate" && echo "$HELP" | grep -q "flowMaxAge"; then
    pass "help_documents_a_and_flowmaxage"
else
    fail "help_documents_a_and_flowmaxage" "help text missing -a or --flowMaxAge"
fi

# 6. -V and --version exit 0 and print a non-empty "pping2 <version>" line
for flag in -V --version; do
    OUT=$("$PPING" $flag 2>/dev/null)
    RC=$?
    if [ "$RC" -eq 0 ] && echo "$OUT" | grep -qE '^pping2 [^ ]+$'; then
        pass "version_flag_$flag"
    else
        fail "version_flag_$flag" "expected exit 0 + 'pping2 <token>'; got rc=$RC out='$OUT'"
    fi
done

# 7. --help first line starts with "pping2 " (version banner present)
HELP_LINE1=$("$PPING" --help 2>&1 | head -1)
if echo "$HELP_LINE1" | grep -qE '^pping2 [^ ]+'; then
    pass "help_version_banner"
else
    fail "help_version_banner" "expected first line to match '^pping2 <token>'; got '$HELP_LINE1'"
fi

# 8. file replay must NOT emit a capture-loss line (pcap_stats is live-only)
CAP_OUT=$("$PPING" -r "$PCAP" 2>&1 >/dev/null)
if echo "$CAP_OUT" | grep -q '^capture:'; then
    fail "no_capture_line_in_file_mode" "file replay emitted a 'capture:' line: $CAP_OUT"
else
    pass "no_capture_line_in_file_mode"
fi

# 9. PPING_FILTER env var is read by the binary itself (systemd no longer
# wraps it through sh -c). A filter matching no packets zeroes the output.
DNSPCAP="$PCAPS_DIR/dns-tcp-linux.pcap"
BASE=$(PPING_FILTER= "$PPING" -a -c 20 -r "$DNSPCAP" 2>/dev/null | wc -l | tr -d ' ')
DROP=$(PPING_FILTER="port 9999" "$PPING" -a -c 20 -r "$DNSPCAP" 2>/dev/null | wc -l | tr -d ' ')
if [ "$BASE" -gt 0 ] && [ "$DROP" -eq 0 ]; then
    pass "env_filter_applied"
else
    fail "env_filter_applied" "base=$BASE drop=$DROP (expected base>0, drop=0)"
fi

# 10. CLI -f wins over PPING_FILTER env (env ignored when -f present)
OVER=$(PPING_FILTER="port 9999" "$PPING" -a -c 20 -f "port 53" -r "$DNSPCAP" 2>/dev/null | wc -l | tr -d ' ')
if [ "$OVER" -gt 0 ]; then
    pass "cli_f_overrides_env"
else
    fail "cli_f_overrides_env" "rows=$OVER (expected >0; -f must win over env)"
fi

summary test_cli
