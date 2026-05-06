#!/bin/sh
# test_cli.sh — CLI surface tests for the aggregator flags.
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAP="$SCRIPT_DIR/known.pcap"

PASS=0
FAIL=0
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

# 1. -a alone runs without error
if "$PPING" -a -r "$PCAP" >/dev/null 2>&1; then
    pass "a_alone_ok"
else
    fail "a_alone_ok" "exit non-zero"
fi

# 2. -a -e is rejected at startup
ERR=$("$PPING" -a -e -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_e_mutex"
else
    fail "a_e_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 3. -a -m is rejected at startup
ERR=$("$PPING" -a -m -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "mutually exclusive"; then
    pass "a_m_mutex"
else
    fail "a_m_mutex" "expected non-zero exit + 'mutually exclusive' in stderr; got rc=$RC stderr=$ERR"
fi

# 4. --flowMaxAge=900 accepted
if "$PPING" -a --flowMaxAge=900 -r "$PCAP" >/dev/null 2>&1; then
    pass "flowMaxAge_900"
else
    fail "flowMaxAge_900" "exit non-zero"
fi

# 5. --flowMaxAge=0 (disable) accepted
if "$PPING" -a --flowMaxAge=0 -r "$PCAP" >/dev/null 2>&1; then
    pass "flowMaxAge_zero"
else
    fail "flowMaxAge_zero" "exit non-zero"
fi

# 6. --flowMaxAge=-1 rejected
ERR=$("$PPING" -a --flowMaxAge=-1 -r "$PCAP" 2>&1 >/dev/null)
RC=$?
if [ "$RC" -ne 0 ] && echo "$ERR" | grep -q "flowMaxAge"; then
    pass "flowMaxAge_negative_rejected"
else
    fail "flowMaxAge_negative_rejected" "expected non-zero exit + flowMaxAge in stderr; got rc=$RC"
fi

# 7. -h/--help mentions -a and --flowMaxAge
HELP=$("$PPING" --help 2>&1)
if echo "$HELP" | grep -q "\-a|--aggregate" && echo "$HELP" | grep -q "flowMaxAge"; then
    pass "help_documents_a_and_flowmaxage"
else
    fail "help_documents_a_and_flowmaxage" "help text missing -a or --flowMaxAge"
fi

# 8. -a flushes every live-at-end flow on -c cap (no measurements lost)
# Run on the existing dns-tcp-linux pcap with -c truncating mid-replay.
# We don't assert the exact count here (depends on packet ordering); we
# only assert that aggregator output is non-empty.
COUNT=$("$PPING" -a -c 20 -r "$SCRIPT_DIR/pcaps/dns-tcp-linux.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt 0 ]; then
    pass "shutdown_flush_emits_rows"
else
    fail "shutdown_flush_emits_rows" "expected non-zero output rows from -c-truncated run"
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "test_cli: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
