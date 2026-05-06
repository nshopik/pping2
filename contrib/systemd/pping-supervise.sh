#!/bin/bash
# pping-supervise.sh — fan one pping process per interface in $PPING_IFACE.
# In the single-interface case spawns a single child; multi-interface case
# spawns one per. All children inherit the unit's stdout so output flows
# into a single /var/log/pping.log atomically. Exits when any child exits
# so the unit's Restart=always brings the group back together.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping
: "${PPING_IFACE:?PPING_IFACE not set in /etc/default/pping}"
PPING_FLAGS="${PPING_FLAGS:-}"

pids=()
shutdown() {
    [ ${#pids[@]} -gt 0 ] && kill "${pids[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

for iface in $PPING_IFACE; do
    /usr/local/bin/pping $PPING_FLAGS -i "$iface" &
    pids+=("$!")
done

if [ ${#pids[@]} -eq 0 ]; then
    echo "fatal: no interfaces parsed from PPING_IFACE='$PPING_IFACE'" >&2
    exit 1
fi

# Exit when any child exits; systemd Restart=always restores the group.
wait -n
exit $?
