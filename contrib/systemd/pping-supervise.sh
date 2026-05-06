#!/bin/bash
# pping-supervise.sh — fan one pping process per interface in $PPING_IFACE.
# In the single-interface case spawns a single child; multi-interface case
# spawns one per. Each pping owns its own --logfile fd; on SIGHUP (sent via
# `systemctl reload pping`) the supervisor propagates the signal so all
# children reopen their log file. Exits when any child exits so the unit's
# Restart=always brings the group back together.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping
: "${PPING_IFACE:?PPING_IFACE not set in /etc/default/pping}"
PPING_FLAGS="${PPING_FLAGS:-}"
PPING_LOGFILE="${PPING_LOGFILE:-/var/log/pping.log}"

pids=()
_shutdown=0
shutdown() {
    _shutdown=1
    [ ${#pids[@]} -gt 0 ] && kill "${pids[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT
trap 'kill -HUP "${pids[@]}" 2>/dev/null || true' HUP

for iface in $PPING_IFACE; do
    [ "$_shutdown" -eq 1 ] && break
    /usr/local/bin/pping --logfile="$PPING_LOGFILE" $PPING_FLAGS -i "$iface" &
    pids+=("$!")
done

if [ ${#pids[@]} -eq 0 ]; then
    echo "fatal: no interfaces parsed from PPING_IFACE='$PPING_IFACE'" >&2
    exit 1
fi

# Exit when any child exits; systemd Restart=always restores the group.
wait -n
exit $?
