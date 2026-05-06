#!/bin/sh
# test_aggregate.sh — diff -a output against goldens for the three existing
# pcap fixtures, plus invariants and synth-fixture checks.
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping"
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

TOTAL=$((PASS + FAIL))
echo ""
echo "test_aggregate: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
