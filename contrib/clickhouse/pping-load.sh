#!/bin/bash
# Batch-load /var/log/pping.log into ClickHouse. Driven by /etc/cron.d/pping-load.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping

LOGFILE=/var/log/pping.log
LOADFILE=/var/log/pping.load.log
TABLE="${PPING_TABLE:-pping_flows}"

[ -f "$LOGFILE" ]    || exit 0    # nothing new to load
[ ! -f "$LOADFILE" ] || exit 0    # previous load still in progress / failed; keep accumulating

mv "$LOGFILE" "$LOADFILE"
tr ' ' '\t' < "$LOADFILE" \
  | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV" \
  && rm "$LOADFILE"
