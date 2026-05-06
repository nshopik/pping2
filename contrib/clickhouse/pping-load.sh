#!/bin/bash
# Batch-load /var/log/pping.log into ClickHouse. Driven by /etc/cron.d/pping-load.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping

LOGFILE=/var/log/pping.log
LOADFILE=/var/log/pping.load.log
TABLE="${PPING_TABLE:-pping_flows}"

[ -s "$LOGFILE" ]    || exit 0    # nothing new to load (file missing or empty)
[ ! -f "$LOADFILE" ] || exit 0    # previous load still in progress / failed; keep accumulating

# cp + truncate, not mv: pping holds an O_APPEND fd on $LOGFILE via systemd's
# StandardOutput=append:. mv would keep that fd alive on the renamed inode,
# and a subsequent rm would orphan it — pping would then write into a deleted
# inode forever. cp + truncate-in-place keeps the inode at $LOGFILE so the fd
# stays valid; new writes resume at offset 0.
cp "$LOGFILE" "$LOADFILE"
: > "$LOGFILE"

if tr ' ' '\t' < "$LOADFILE" \
     | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"; then
    rm "$LOADFILE"
else
    echo "$(date -Iseconds) pping-load: clickhouse-client failed; preserving $LOADFILE for next run" >&2
    exit 1
fi
