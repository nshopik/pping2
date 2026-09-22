#!/bin/sh
# test_integration.sh — diff -m and -e output against goldens for known.pcap.
# POSIX sh.
#
# The goldens pin every field of every line, so they subsume the per-field
# shape checks (field count, rtt/minRTT values, dotted IPs, numeric ports,
# tag column) that used to live in a separate test_format.sh.
#
# Regenerate goldens with `make goldens`.
. "$(dirname "$0")/lib.sh"

PCAP="$PCAPS_DIR/known.pcap"
ACTUAL=$(mktemp)
trap 'rm -f "$ACTUAL"' EXIT INT TERM

# 1. -m output matches golden.
"$PPING" -m -r "$PCAP" 2>/dev/null > "$ACTUAL"
if diff -q "$GOLDEN_DIR/known.m.golden" "$ACTUAL" >/dev/null 2>&1; then
    pass "m_output_matches_golden"
else
    fail "m_output_matches_golden" "stdout differs"
    diff -u "$GOLDEN_DIR/known.m.golden" "$ACTUAL" | head -40
fi

# 2. -e output matches golden. Strip col 11 (node/hostname) so the golden is
#    portable across machines, as test_seq.sh does.
"$PPING" -e -r "$PCAP" 2>/dev/null \
    | awk '{$11=""; gsub(/  +/, " "); print}' > "$ACTUAL"
if diff -q "$GOLDEN_DIR/known.e.golden" "$ACTUAL" >/dev/null 2>&1; then
    pass "e_output_matches_golden"
else
    fail "e_output_matches_golden" "stdout differs"
    diff -u "$GOLDEN_DIR/known.e.golden" "$ACTUAL" | head -40
fi

# 3. -e node column is non-empty. Stripped from the golden, so checked here.
BAD_NODE=$("$PPING" -e -r "$PCAP" 2>/dev/null | awk 'NF != 12 || $11 == "" { print NR }')
if [ -z "$BAD_NODE" ]; then
    pass "e_node_nonempty"
else
    fail "e_node_nonempty" "lines with empty/missing node: $BAD_NODE"
fi

summary integration
