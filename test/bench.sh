#!/bin/sh
# test/bench.sh — multi-mode latency harness for pping2.
#
# Runs 1 warmup + 10 timed iterations per mode, computes median/p10/p90/Mpps.
# Modes: -a hybrid, -m hybrid, human hybrid, -e hybrid.
#
# Input priority:
#   1. ~/bench.pcap if present (real traffic, low noise)
#   2. All test/pcaps/*.pcap fixtures concatenated (noisy — numbers not
#      actionable, but harness still exercises all code paths).
#
# POSIX sh + awk + sort -n.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAPS_DIR="$SCRIPT_DIR/pcaps"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built" >&2
    exit 1
fi

# --- Choose input file ---
BENCH_PCAP="${BENCH_PCAP:-$HOME/bench.pcap}"
USING_FIXTURE=0
_TMPPCAP=""
if [ ! -f "$BENCH_PCAP" ]; then
    # Fall back: merge all six test/pcaps/*.pcap fixtures into a temp file.
    # mergecap (from wireshark-common) preferred; if absent, use the first
    # fixture alone (pping can only read one file per -r invocation).
    FIXTURE_PCAPS=$(ls "$PCAPS_DIR"/*.pcap 2>/dev/null)
    if [ -z "$FIXTURE_PCAPS" ]; then
        echo "ERROR: no pcap found (set BENCH_PCAP or ensure test/pcaps/ is populated)" >&2
        exit 1
    fi
    if command -v mergecap >/dev/null 2>&1; then
        _TMPPCAP=$(mktemp /tmp/bench-fixtures.XXXXXX.pcap)
        # shellcheck disable=SC2086
        mergecap -w "$_TMPPCAP" $FIXTURE_PCAPS
        BENCH_PCAP="$_TMPPCAP"
        trap 'rm -f "$_TMPPCAP"' EXIT
    else
        # mergecap absent: use largest fixture as single representative
        BENCH_PCAP=$(ls -S "$PCAPS_DIR"/*.pcap 2>/dev/null | head -1)
    fi
    USING_FIXTURE=1
fi

# Packet count from pcap global header + record headers (portable awk approach)
# pping stderr summary reports pkt count; grab it from a single run.
PKT_COUNT=$("$PPING" -v --mode hybrid -r "$BENCH_PCAP" 2>&1 1>/dev/null \
            | awk '/^wall-clock/ { for (i=1;i<=NF;i++) if ($i=="packets") { print $(i-1); exit } }')
PKT_COUNT="${PKT_COUNT:-unknown}"

# --- Header ---
ITERS=10
GIT_SHORT=$(git -C "$SCRIPT_DIR/.." rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git -C "$SCRIPT_DIR/.." rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
KERNEL=$(uname -sr)
GCC_VER=$(gcc --version 2>/dev/null | head -1 | awk '{print $NF}' || echo "unknown")
TINS_VER=$(pkg-config --modversion libtins 2>/dev/null || echo "unknown")

echo "fixture: $BENCH_PCAP ($PKT_COUNT packets)"
echo "env: $KERNEL  gcc $GCC_VER  libtins $TINS_VER"
echo "git: $GIT_SHORT ($GIT_BRANCH)"
echo "iters: $ITERS/run"
if [ "$USING_FIXTURE" -eq 1 ]; then
    echo "WARNING: using small fixture pcap — numbers are too noisy to act on"
fi
echo ""

# --- Column header ---
printf '%-12s %-8s %-8s %-8s %-8s\n' "mode" "median" "p10" "p90" "Mpps"
printf '%-12s %-8s %-8s %-8s %-8s\n' "----" "------" "---" "---" "----"

# run_mode <label> <extra_args...>
# Runs ITERS+1 iterations (first discarded as warmup), collects ns/pkt,
# sorts, picks p10/median/p90, derives Mpps.
run_mode() {
    label="$1"
    shift
    extra_args="$*"

    # Collect ns/pkt from each run into a temp file
    samples=$(mktemp)
    # warmup (discarded)
    "$PPING" $extra_args --mode hybrid -r "$BENCH_PCAP" >/dev/null 2>/dev/null || true
    i=0
    while [ $i -lt $ITERS ]; do
        ns=$("$PPING" $extra_args --mode hybrid -r "$BENCH_PCAP" 2>&1 1>/dev/null \
             | awk '/^wall-clock/ { for (j=1;j<=NF;j++) if ($j=="ns/pkt,") { print $(j-1); exit } }')
        if [ -n "$ns" ]; then
            echo "$ns" >> "$samples"
        fi
        i=$((i + 1))
    done

    # Sort numeric, pick p10=line1, median=line5, p90=line9
    sorted=$(sort -n "$samples")
    rm -f "$samples"

    p10=$(echo "$sorted"    | awk 'NR==1  {print $1}')
    median=$(echo "$sorted" | awk 'NR==5 {print $1}')
    p90=$(echo "$sorted"    | awk 'NR==9 {print $1}')

    # Mpps = 1000 / median_ns  (median in ns → million pkts per second)
    mpps=$(echo "$median" | awk '{printf "%.2f", 1000.0 / $1}')

    printf '%-12s %-8s %-8s %-8s %-8s\n' \
        "$label" \
        "${median:-?}" \
        "${p10:-?}" \
        "${p90:-?}" \
        "${mpps:-?}"
}

run_mode "-a hybrid"    -a
run_mode "-m hybrid"    -m
run_mode "human"
run_mode "-e hybrid"    -e
