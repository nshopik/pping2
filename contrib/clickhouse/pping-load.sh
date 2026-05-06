#!/bin/bash
# Batch-load pping's log file into ClickHouse. Driven by /etc/cron.d/pping-load.
#
# Rotation is fast and zero-copy: mv is atomic at the dirent level (same fs);
# pping holds an O_APPEND fd on the original inode (now at $LOADFILE). We
# then `systemctl reload pping` which sends SIGHUP through the supervisor
# down to each pping child, and they reopen their --logfile path — which
# now points to a fresh empty file. Old data is in $LOADFILE; new data
# accumulates in $LOGFILE.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping

LOGFILE="${PPING_LOGFILE:-/var/log/pping.log}"
LOADFILE="${LOGFILE}.load"
TABLE="${PPING_TABLE:-pping_flows}"

[ -s "$LOGFILE" ]    || exit 0    # nothing new to load (file missing or empty)
[ ! -f "$LOADFILE" ] || exit 0    # previous load still in progress / failed; keep accumulating

mv "$LOGFILE" "$LOADFILE"
if ! systemctl reload pping.service 2>/dev/null; then
    echo "$(date -Iseconds) pping-load: systemctl reload pping failed; pping is still writing to $LOADFILE — aborting load to preserve data" >&2
    exit 1
fi

if tr ' ' '\t' < "$LOADFILE" \
     | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"; then
    rm "$LOADFILE"
else
    echo "$(date -Iseconds) pping-load: clickhouse-client failed; preserving $LOADFILE for next run" >&2
    exit 1
fi
