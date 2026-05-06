#!/bin/bash
# Batch-load pping's log file into ClickHouse. Driven by /etc/cron.d/pping-load.
#
# Rotation is fast and zero-copy: mv is atomic at the dirent level (same fs);
# pping holds an O_APPEND fd on the original inode (now at $LOADFILE). We
# then `systemctl reload pping` which sends SIGHUP through to pping, and it
# reopens its --logfile path — which now points to a fresh empty file. Old
# data is in $LOADFILE; new data accumulates in $LOGFILE.
#
# Two ingest paths: clickhouse-client (default) and curl (HTTP interface).
# See /etc/default/pping for configuration.
set -euo pipefail

[ -r /etc/default/pping ] && . /etc/default/pping

LOGFILE="${PPING_LOGFILE:-/var/log/pping.log}"
LOADFILE="${LOGFILE}.load"
TABLE="${PPING_TABLE:-pping_flows}"
INGEST="${PPING_INGEST:-clickhouse-client}"

[ -s "$LOGFILE" ]    || exit 0    # nothing new to load (file missing or empty)
[ ! -f "$LOADFILE" ] || exit 0    # previous load still in progress / failed; keep accumulating

mv "$LOGFILE" "$LOADFILE"
if ! systemctl reload pping.service 2>/dev/null; then
    echo "$(date -Iseconds) pping-load: systemctl reload pping failed; pping is still writing to $LOADFILE — aborting load to preserve data" >&2
    exit 1
fi

ingest_via_clickhouse_client() {
    tr ' ' '\t' < "$LOADFILE" \
      | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"
}

ingest_via_curl() {
    : "${CH_URL:?CH_URL not set in /etc/default/pping (required when PPING_INGEST=curl)}"
    local full_table="${CH_DATABASE:+${CH_DATABASE}.}${TABLE}"
    local auth_arg=""
    [ -n "${CH_AUTH:-}" ] && auth_arg="-u $CH_AUTH"
    {
        echo "INSERT INTO ${full_table} FORMAT TabSeparated"
        tr ' ' '\t' < "$LOADFILE"
    } | curl -sS -f $auth_arg ${CH_CURL_OPTS:-} "$CH_URL/" --data-binary @-
}

case "$INGEST" in
    clickhouse-client) ingest_fn=ingest_via_clickhouse_client ;;
    curl)              ingest_fn=ingest_via_curl ;;
    *)
        echo "$(date -Iseconds) pping-load: unknown PPING_INGEST='$INGEST' (expected 'clickhouse-client' or 'curl')" >&2
        exit 1
        ;;
esac

if "$ingest_fn"; then
    rm "$LOADFILE"
else
    echo "$(date -Iseconds) pping-load: $INGEST ingest failed; preserving $LOADFILE for next run" >&2
    exit 1
fi
