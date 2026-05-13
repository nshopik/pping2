#!/bin/sh
# test_aggregate.sh — diff -a output against goldens for the three existing
# pcap fixtures, plus invariants and synth-fixture checks.
# POSIX sh.
#
# Regenerating goldens: see test_seq.sh header for the full procedure;
# the aggregate recipe uses '-a', strips col 8 (node), and pipes through sort.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAPS_DIR="$SCRIPT_DIR/pcaps"
GOLDEN_DIR="$SCRIPT_DIR/golden"

PASS=0
FAIL=0
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

# 1-3. Per-fixture golden diff. Strip col 8 (node/hostname) for portability.
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    actual=$(mktemp)
    golden="$GOLDEN_DIR/$pcap.aggregate.golden"
    "$PPING" -a -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null \
        | awk '{$8=""; gsub(/  +/, " "); print}' | sort \
        > "$actual"
    if diff -q "$golden" "$actual" >/dev/null 2>&1; then
        pass "aggregate_$pcap"
    else
        fail "aggregate_$pcap" "diff $golden vs actual"
        diff -u "$golden" "$actual" | head -40
    fi
    rm -f "$actual"
done

# 4. Cross-mode invariant: sum(n_samples in -a) == row count in -e for the same pcap.
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    e_rows=$("$PPING" -e -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null | wc -l | tr -d ' ')
    a_sum=$("$PPING" -a -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null \
            | awk '{s+=$3} END {print s+0}')
    if [ "$e_rows" -eq "$a_sum" ]; then
        pass "invariant_${pcap}_n_samples_eq_e_rows"
    else
        fail "invariant_${pcap}_n_samples_eq_e_rows" "e_rows=$e_rows a_sum=$a_sum"
    fi
done

# --- Synth fixtures ---

# 7. age_cap.pcap with --flowMaxAge=5: long flow emits >=2 rows.
ROWS=$("$PPING" -a --flowMaxAge=5 -r "$PCAPS_DIR/age_cap.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$ROWS" -ge 2 ]; then
    pass "age_cap_emits_multiple_rows"
else
    fail "age_cap_emits_multiple_rows" "expected >=2 rows; got $ROWS"
fi

# 8. idle.pcap with --tsvalMaxAge=1 --flowMaxIdle=2: silent flow A emits
#    its row using last_tm (~1e9 + 0.05), not capTm at the cleanUp tick.
#    Strip node col, sort, take only Flow A's source IP rows.
A_ROWS=$("$PPING" -a --tsvalMaxAge=1 --flowMaxIdle=2 \
            -r "$PCAPS_DIR/idle.pcap" 2>/dev/null \
         | awk '$4 == "10.0.0.10"')
A_COUNT=$(echo "$A_ROWS" | grep -c '^.')
A_TS=$(echo "$A_ROWS" | head -1 | awk '{print $1}')
if [ "$A_COUNT" -ge 1 ] && echo "$A_TS" | grep -qE '^1000000000\.0[45]'; then
    pass "idle_uses_last_tm_not_cleanup_tick"
else
    fail "idle_uses_last_tm_not_cleanup_tick" \
         "A_COUNT=$A_COUNT first_ts=$A_TS (expected 1000000000.04xxxx or .05xxxx)"
fi

# 9. no_synack.pcap: -a should produce zero output rows.
NS_ROWS=$("$PPING" -a -r "$PCAPS_DIR/no_synack.pcap" 2>/dev/null | wc -l | tr -d ' ')
if [ "$NS_ROWS" -eq 0 ]; then
    pass "no_synack_silent_delete"
else
    fail "no_synack_silent_delete" "expected 0 rows; got $NS_ROWS"
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "test_aggregate: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
