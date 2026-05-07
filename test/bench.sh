#!/bin/sh
# bench.sh — print ns/pkt + Mpps for each (pcap, mode) pair.
# pping's wall-clock summary is the source of these numbers; this script
# just runs the matrix and tabulates.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAPS_DIR="$SCRIPT_DIR/pcaps"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built"
    exit 1
fi

printf '%-22s %-8s %-12s %-10s\n' pcap mode ns/pkt Mpps
printf '%-22s %-8s %-12s %-10s\n' '----' '----' '------' '----'
for pcap in dns-tcp-linux dns-tcp-windows mixed-with-retx; do
    for m in ts seq hybrid; do
        # capTm-based mode is silent in pcap mode, so force a summary with -v.
        line=$("$PPING" -v --mode "$m" -r "$PCAPS_DIR/$pcap.pcap" 2>&1 1>/dev/null \
              | grep '^wall-clock')
        ns=$(echo "$line" | awk '{ for (i=1;i<=NF;i++) if ($i=="ns/pkt,") print $(i-1) }')
        mpps=$(echo "$line" | awk '{ for (i=1;i<=NF;i++) if ($i=="Mpps") print $(i-1) }')
        printf '%-22s %-8s %-12s %-10s\n' "$pcap" "$m" "${ns:-?}" "${mpps:-?}"
    done
done
