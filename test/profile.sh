#!/bin/sh
# test/profile.sh — capture a DWARF perf profile of pping2 -a --mode hybrid.
#
# Loops the pping invocation enough times to accumulate >=1,000 samples at
# -F 999 (target ~10 s of profiled runtime). Output written to:
#   docs/superpowers/baselines/YYYY-MM-DD-profile-a-hybrid-<short>.txt
#
# Environment overrides:
#   BENCH_PCAP  path to input pcap  (default: ~/bench.pcap)
#   LOOPS       iteration count     (default: 50)
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PPING="$SCRIPT_DIR/../pping2"
PCAP="${BENCH_PCAP:-$HOME/bench.pcap}"
LOOPS="${LOOPS:-50}"

if [ ! -x "$PPING" ]; then
    echo "ERROR: $PPING not built" >&2
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "ERROR: $PCAP missing — capture a real pcap before profiling." >&2
    echo "       (Fixture pcaps are too small for meaningful sample counts.)" >&2
    exit 1
fi

paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "unknown")
if [ "$paranoid" != "unknown" ] && [ "$paranoid" -gt 2 ]; then
    echo "WARNING: kernel.perf_event_paranoid=$paranoid; perf may produce no samples." >&2
    echo "         To fix: sudo sysctl -w kernel.perf_event_paranoid=1" >&2
fi

if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: perf not found — install linux-tools-$(uname -r) or linux-tools-common" >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR/../docs/superpowers/baselines"

DATA=$(mktemp -t pping-profile.XXXXXX.data)
trap 'rm -f "$DATA"' EXIT

echo "profiling: $LOOPS loops of '$PPING -a --mode hybrid -r $PCAP' ..."

perf record -F 999 --call-graph dwarf -o "$DATA" -- \
    sh -c "for i in \$(seq 1 $LOOPS); do \"$PPING\" -a --mode hybrid -r \"$PCAP\" > /dev/null; done"

GIT_SHORT=$(git -C "$SCRIPT_DIR/.." rev-parse --short HEAD 2>/dev/null || echo "unknown")
OUT="$SCRIPT_DIR/../docs/superpowers/baselines/$(date -u +%Y-%m-%d)-profile-a-hybrid-${GIT_SHORT}.txt"

{
    echo "# profile: -a --mode hybrid on $PCAP x $LOOPS loops"
    echo "# git: $GIT_SHORT"
    echo "# env: $(uname -srvmpo 2>/dev/null || uname -srm)"
    echo "# perf_event_paranoid: $paranoid"
    echo ""
    perf report -i "$DATA" --stdio --children -g none --percent-limit 1.0
} > "$OUT"

echo "wrote $OUT"
