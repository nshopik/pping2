#!/bin/sh
# test_format.sh — output format regression tests for pping
#
# Validates -e (extended) and -m (machine-readable) output field structure
# against test/known.pcap.  Must be POSIX sh-compatible.

# Resolve the directory this script lives in so it can be called from anywhere.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
PCAP="$SCRIPT_DIR/known.pcap"

# Temp files; cleaned up on exit.
TMP_E=$(mktemp)
TMP_M=$(mktemp)
trap 'rm -f "$TMP_E" "$TMP_M"' EXIT INT TERM

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
# Capture -e and -m output once
# ---------------------------------------------------------------------------
"$PPING" -e -r "$PCAP" > "$TMP_E" 2>/dev/null
"$PPING" -m -r "$PCAP" > "$TMP_M" 2>/dev/null

# ---------------------------------------------------------------------------
# 1. e_line_count — -e output has exactly 4 lines
# ---------------------------------------------------------------------------
LINE_COUNT=$(wc -l < "$TMP_E" | tr -d ' ')
if [ "$LINE_COUNT" -eq 4 ]; then
    pass "e_line_count"
else
    fail "e_line_count" "expected 4 lines, got $LINE_COUNT"
fi

# ---------------------------------------------------------------------------
# 2. e_field_count — every -e line has exactly 12 fields
# ---------------------------------------------------------------------------
BAD_FIELDS=$(awk 'NF != 12 { print NR": "NF" fields: "$0 }' "$TMP_E")
if [ -z "$BAD_FIELDS" ]; then
    pass "e_field_count"
else
    fail "e_field_count" "lines with wrong field count: $BAD_FIELDS"
fi

# ---------------------------------------------------------------------------
# 2b. e_tag_field — field 12 is 't' (TS path) on every line for known.pcap
# ---------------------------------------------------------------------------
BAD_TAG=$(awk '$12 != "t" { print NR": "$12 }' "$TMP_E")
if [ -z "$BAD_TAG" ]; then
    pass "e_tag_field"
else
    fail "e_tag_field" "lines with wrong tag: $BAD_TAG"
fi

# ---------------------------------------------------------------------------
# 3. e_timestamp_numeric — field 1 matches [0-9]*\.[0-9]* on every line
# ---------------------------------------------------------------------------
BAD_TS=$(awk '$1 !~ /^[0-9]+\.[0-9]+$/ { print NR": "$1 }' "$TMP_E")
if [ -z "$BAD_TS" ]; then
    pass "e_timestamp_numeric"
else
    fail "e_timestamp_numeric" "lines with bad timestamp: $BAD_TS"
fi

# ---------------------------------------------------------------------------
# 4. e_rtt_format — field 2 (rtt) is 0.050000 on every line
# ---------------------------------------------------------------------------
BAD_RTT=$(awk '$2 != "0.050000" { print NR": "$2 }' "$TMP_E")
if [ -z "$BAD_RTT" ]; then
    pass "e_rtt_format"
else
    fail "e_rtt_format" "lines with wrong rtt: $BAD_RTT"
fi

# ---------------------------------------------------------------------------
# 5. e_minrtt_format — field 3 (minRTT) is 0.050000 on every line
# ---------------------------------------------------------------------------
BAD_MIN=$(awk '$3 != "0.050000" { print NR": "$3 }' "$TMP_E")
if [ -z "$BAD_MIN" ]; then
    pass "e_minrtt_format"
else
    fail "e_minrtt_format" "lines with wrong minRTT: $BAD_MIN"
fi

# ---------------------------------------------------------------------------
# 6. e_srcip_dotted — field 7 (srcIP) contains a dot (IPv4 sanity)
# ---------------------------------------------------------------------------
BAD_SRCIP=$(awk '$7 !~ /\./ { print NR": "$7 }' "$TMP_E")
if [ -z "$BAD_SRCIP" ]; then
    pass "e_srcip_dotted"
else
    fail "e_srcip_dotted" "lines with bad srcIP: $BAD_SRCIP"
fi

# ---------------------------------------------------------------------------
# 7. e_dstip_dotted — field 9 (dstIP) contains a dot
# ---------------------------------------------------------------------------
BAD_DSTIP=$(awk '$9 !~ /\./ { print NR": "$9 }' "$TMP_E")
if [ -z "$BAD_DSTIP" ]; then
    pass "e_dstip_dotted"
else
    fail "e_dstip_dotted" "lines with bad dstIP: $BAD_DSTIP"
fi

# ---------------------------------------------------------------------------
# 8. e_sport_numeric — field 8 (sport) matches [0-9]+
# ---------------------------------------------------------------------------
BAD_SPORT=$(awk '$8 !~ /^[0-9]+$/ { print NR": "$8 }' "$TMP_E")
if [ -z "$BAD_SPORT" ]; then
    pass "e_sport_numeric"
else
    fail "e_sport_numeric" "lines with non-numeric sport: $BAD_SPORT"
fi

# ---------------------------------------------------------------------------
# 9. e_dport_numeric — field 10 (dport) matches [0-9]+
# ---------------------------------------------------------------------------
BAD_DPORT=$(awk '$10 !~ /^[0-9]+$/ { print NR": "$10 }' "$TMP_E")
if [ -z "$BAD_DPORT" ]; then
    pass "e_dport_numeric"
else
    fail "e_dport_numeric" "lines with non-numeric dport: $BAD_DPORT"
fi

# ---------------------------------------------------------------------------
# 10. e_node_nonempty — field 11 (node) is non-empty on every line
# ---------------------------------------------------------------------------
BAD_NODE=$(awk 'NF >= 11 && $11 == "" { print NR": empty node" } NF < 11 { print NR": missing node field" }' "$TMP_E")
if [ -z "$BAD_NODE" ]; then
    pass "e_node_nonempty"
else
    fail "e_node_nonempty" "lines with empty/missing node: $BAD_NODE"
fi

# ---------------------------------------------------------------------------
# 11. m_field_count — every -m line has exactly 4 fields
# ---------------------------------------------------------------------------
BAD_M_FIELDS=$(awk 'NF != 4 { print NR": "NF" fields: "$0 }' "$TMP_M")
if [ -z "$BAD_M_FIELDS" ]; then
    pass "m_field_count"
else
    fail "m_field_count" "lines with wrong field count: $BAD_M_FIELDS"
fi

# ---------------------------------------------------------------------------
# 12. m_rtt_format — field 2 (rtt) is 0.050000 on every -m line
# ---------------------------------------------------------------------------
BAD_M_RTT=$(awk '$2 != "0.050000" { print NR": "$2 }' "$TMP_M")
if [ -z "$BAD_M_RTT" ]; then
    pass "m_rtt_format"
else
    fail "m_rtt_format" "lines with wrong rtt: $BAD_M_RTT"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo ""
echo "format: $PASS/$TOTAL checks passed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
