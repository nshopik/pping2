#!/bin/sh
# test_seq.sh — diff -e --mode <m> output against goldens for SEQ/ACK feature.
# POSIX sh.
#
# Regenerate goldens with `make goldens` (after `make pcaps` if test/synth/ changed).
. "$(dirname "$0")/lib.sh"

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

# A flow takes the same path in hybrid as in its single-path mode: TS-capable
# flows match --mode ts, non-TS flows match --mode seq.
for pair in dns-tcp-linux.ts dns-tcp-windows.seq; do
    if cmp -s "$GOLDEN_DIR/$pair.golden" "$GOLDEN_DIR/${pair%.*}.hybrid.golden"; then
        pass "parity_$pair"
    else
        fail "parity_$pair" "$pair.golden differs from ${pair%.*}.hybrid.golden"
    fi
done

summary test_seq
