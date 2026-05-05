#!/bin/sh
# test_integration.sh — integration tests for pping
#
# Runs pping against the synthetic known.pcap and checks output.
# Must be POSIX sh-compatible.

# Resolve the directory this script lives in so it can be called from anywhere.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAP="$SCRIPT_DIR/known.pcap"
GOLDEN="$SCRIPT_DIR/known.pcap.golden"

# Temp files; cleaned up on exit.
TMP_M=$(mktemp)
TMP_E=$(mktemp)
trap 'rm -f "$TMP_M" "$TMP_E"' EXIT INT TERM

PASS=0
FAIL=0

pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

# ---------------------------------------------------------------------------
# Pre-flight: binary exists and is executable
# ---------------------------------------------------------------------------
if [ ! -e "$PPING" ]; then
    echo "ERROR: pping binary not found at $PPING"
    echo "       Build it first with: make"
    exit 1
fi
if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING exists but is not executable"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. -m output matches golden file
# ---------------------------------------------------------------------------
"$PPING" -m -r "$PCAP" > "$TMP_M" 2>/dev/null
if diff -q "$GOLDEN" "$TMP_M" > /dev/null 2>&1; then
    pass "m_output_matches_golden"
else
    fail "m_output_matches_golden" "stdout differs from $GOLDEN"
    echo "--- expected ($GOLDEN) ---"
    cat "$GOLDEN"
    echo "--- got ($TMP_M) ---"
    cat "$TMP_M"
fi

# ---------------------------------------------------------------------------
# 2. -m produces exactly 4 lines
# ---------------------------------------------------------------------------
LINE_COUNT=$(wc -l < "$TMP_M" | tr -d ' ')
if [ "$LINE_COUNT" -eq 4 ]; then
    pass "m_line_count_is_4"
else
    fail "m_line_count_is_4" "expected 4 lines, got $LINE_COUNT"
fi

# ---------------------------------------------------------------------------
# 3. -e output: each line has exactly 12 fields
# ---------------------------------------------------------------------------
"$PPING" -e -r "$PCAP" > "$TMP_E" 2>/dev/null

BAD_FIELDS=$(awk 'NF != 12 { print NR": "NF" fields: "$0 }' "$TMP_E")
if [ -z "$BAD_FIELDS" ]; then
    pass "e_field_count_12"
else
    fail "e_field_count_12" "lines with wrong field count: $BAD_FIELDS"
fi

# ---------------------------------------------------------------------------
# 3b. e_tag_field — field 12 is 't' (TS path) on every line for known.pcap
# ---------------------------------------------------------------------------
BAD_TAG=$(awk '$12 != "t" { print NR": "$12 }' "$TMP_E")
if [ -z "$BAD_TAG" ]; then
    pass "e_tag_field"
else
    fail "e_tag_field" "lines with wrong tag: $BAD_TAG"
fi

# ---------------------------------------------------------------------------
# 4. -e field 2 (rtt) is 0.050000 on every line
# ---------------------------------------------------------------------------
BAD_RTT=$(awk '$2 != "0.050000" { print NR": "$2 }' "$TMP_E")
if [ -z "$BAD_RTT" ]; then
    pass "e_rtt_field_correct"
else
    fail "e_rtt_field_correct" "lines with wrong rtt: $BAD_RTT"
fi

# ---------------------------------------------------------------------------
# 5. -e field 3 (minRTT) is 0.050000 on every line
# ---------------------------------------------------------------------------
BAD_MIN=$(awk '$3 != "0.050000" { print NR": "$3 }' "$TMP_E")
if [ -z "$BAD_MIN" ]; then
    pass "e_minrtt_field_correct"
else
    fail "e_minrtt_field_correct" "lines with wrong minRTT: $BAD_MIN"
fi

# ---------------------------------------------------------------------------
# 6. -e field 7 (srcIP) and field 9 (dstIP) contain dots (valid IPv4)
# ---------------------------------------------------------------------------
BAD_SRCIP=$(awk '$7 !~ /\./ { print NR": "$7 }' "$TMP_E")
if [ -z "$BAD_SRCIP" ]; then
    pass "e_srcip_is_dotted"
else
    fail "e_srcip_is_dotted" "lines with bad srcIP: $BAD_SRCIP"
fi

BAD_DSTIP=$(awk '$9 !~ /\./ { print NR": "$9 }' "$TMP_E")
if [ -z "$BAD_DSTIP" ]; then
    pass "e_dstip_is_dotted"
else
    fail "e_dstip_is_dotted" "lines with bad dstIP: $BAD_DSTIP"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo ""
echo "integration: $PASS/$TOTAL checks passed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
