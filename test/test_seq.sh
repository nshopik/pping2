#!/bin/sh
# test_seq.sh — diff -e --mode <m> output against goldens for SEQ/ACK feature.
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAPS_DIR="$SCRIPT_DIR/pcaps"
GOLDEN_DIR="$SCRIPT_DIR/golden"

PASS=0
FAIL=0
pass() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built; run 'make' first"
    exit 1
fi

for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    for m in ts seq hybrid; do
        actual=$(mktemp)
        golden="$GOLDEN_DIR/$pcap.$m.golden"
        # Strip col 11 (node/hostname) so goldens are portable across machines.
        # -e format: ts rtt minRTT fB dB pB srcIP sport dstIP dport node tag
        "$PPING" -e --mode "$m" -r "$PCAPS_DIR/$pcap.pcap" 2>/dev/null \
            | awk '{$11=""; gsub(/  +/, " "); print}' \
            > "$actual"
        if diff -q "$golden" "$actual" >/dev/null 2>&1; then
            pass "$pcap/$m"
        else
            fail "$pcap/$m" "diff $golden vs actual"
            diff -u "$golden" "$actual" | head -40
        fi
        rm -f "$actual"
    done
done

TOTAL=$((PASS + FAIL))
echo ""
echo "test_seq: $PASS/$TOTAL checks passed"
[ $FAIL -gt 0 ] && exit 1
exit 0
