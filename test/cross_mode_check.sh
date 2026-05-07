#!/bin/sh
# cross_mode_check.sh — assert TS-only flows produce identical samples in
# --mode ts and --mode hybrid (modulo the tag column, which is 't' in both).
# POSIX sh.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAP="$SCRIPT_DIR/pcaps/dns-tcp-linux.pcap"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

TS=$(mktemp); HY=$(mktemp)
trap 'rm -f "$TS" "$HY"' EXIT INT TERM

# -e format columns: ts rtt minRTT fB dB pB srcIP sport dstIP dport node tag.
# Both runs are on the same host so col 11 (node) will match, but we strip
# anyway for consistency with test_seq.sh.
"$PPING" -e --mode ts     -r "$PCAP" 2>/dev/null \
    | awk '{$11=""; gsub(/  +/, " "); print}' > "$TS"
"$PPING" -e --mode hybrid -r "$PCAP" 2>/dev/null \
    | awk '{$11=""; gsub(/  +/, " "); print}' > "$HY"

if diff -q "$TS" "$HY" >/dev/null 2>&1; then
    printf 'PASS cross_mode_parity_dns_tcp_linux\n'
else
    printf 'FAIL cross_mode_parity_dns_tcp_linux: diff between --mode ts and --mode hybrid\n'
    diff -u "$TS" "$HY" | head -40
    exit 1
fi

# Sanity: every line must end in tag 't' (no SEQ samples on a TS-capable pcap).
BAD=$(awk '$NF != "t" { print NR": "$NF }' "$HY")
if [ -z "$BAD" ]; then
    printf 'PASS cross_mode_hybrid_all_t_tags\n'
else
    printf 'FAIL cross_mode_hybrid_all_t_tags: %s\n' "$BAD"
    exit 1
fi

exit 0
