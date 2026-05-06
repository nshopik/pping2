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

# All diagnostic output goes through `logger -s` so it lands in
# syslog/journal AND on stderr (the latter reaches cron mail when an MTA
# is configured). Without this, a misconfigured CH host or a stuck
# .load file produces no visible signal on systems with no MTA — the
# common "everything looks fine but no data is loading" failure mode.
log() {
    local level=$1; shift
    logger -s -t pping-load -p "daemon.$level" -- "$*"
}

[ -r /etc/default/pping ] && . /etc/default/pping

# tr ' ' '\t' below assumes pping's space-separated output has no spaces
# inside fields. True for the current `-a` / `-e` formats (numerics, IPs,
# RFC-bound FQDNs, single-char tags). If pping ever gains a field that
# can contain spaces, this loader needs an awk/perl reformatter.

LOGFILE="${PPING_LOGFILE:-/var/log/pping/pping.log}"
LOADFILE="${LOGFILE}.load"
TABLE="${PPING_TABLE:-pping_flows}"
INGEST="${PPING_INGEST:-clickhouse-client}"

# Previous load failed: don't rotate again, just skip. Warn loudly so a
# stuck .load (e.g. CH unreachable, bad CH_ARGS) is visible in syslog/journal
# instead of accumulating silently. Checked before LOGFILE so even a quiet
# pping (no new rows) still surfaces the stuck file once a minute.
if [ -f "$LOADFILE" ]; then
    log warning "$LOADFILE present from previous run; skipping ingest until it is resolved"
    exit 0
fi

[ -s "$LOGFILE" ] || exit 0    # nothing new to load (file missing or empty); silent — normal case

mv "$LOGFILE" "$LOADFILE"
if ! systemctl reload pping.service; then
    log err "systemctl reload pping failed; pping is still writing to $LOADFILE — aborting load to preserve data"
    exit 1
fi

ingest_via_clickhouse_client() {
    tr ' ' '\t' < "$LOADFILE" \
      | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"
}

ingest_via_curl() {
    : "${CH_URL:?CH_URL not set in /etc/default/pping (required when PPING_INGEST=curl)}"
    local full_table="${CH_DATABASE:+${CH_DATABASE}.}${TABLE}"
    local auth_arg=()
    [ -n "${CH_AUTH:-}" ] && auth_arg=(-u "$CH_AUTH")
    {
        echo "INSERT INTO ${full_table} FORMAT TabSeparated"
        tr ' ' '\t' < "$LOADFILE"
    } | curl -sS -f "${auth_arg[@]}" ${CH_CURL_OPTS:-} "$CH_URL/" --data-binary @-
}

case "$INGEST" in
    clickhouse-client) ingest_fn=ingest_via_clickhouse_client ;;
    curl)              ingest_fn=ingest_via_curl ;;
    *)
        log err "unknown PPING_INGEST='$INGEST' (expected 'clickhouse-client' or 'curl')"
        exit 1
        ;;
esac

# Route the ingest tool's stderr through logger so its diagnostic
# (e.g. "Code: 209. DB::NetException: Connection refused" from
# clickhouse-client, or curl's resolve/SSL errors) reaches syslog/journal.
# Process substitution requires bash, which the shebang already mandates.
if "$ingest_fn" 2> >(logger -s -t pping-load -p daemon.err); then
    rm "$LOADFILE"
else
    log err "$INGEST ingest failed; preserving $LOADFILE for next run"
    exit 1
fi
