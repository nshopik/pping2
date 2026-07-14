#!/bin/bash
# Batch-load pping2's log file into ClickHouse. Driven by /etc/cron.d/pping2-load.
#
# Rotation: mv $LOGFILE → $LOADFILE (atomic, same fs), then SIGHUP pping2 via
# `systemctl reload` so it reopens --logfile at a fresh empty $LOGFILE. Old
# data ingests from $LOADFILE; new data accumulates in $LOGFILE.
#
# Two ingest paths: clickhouse-client (default) and curl. Config in
# /etc/default/pping2.
set -euo pipefail

# logger -s: diagnostics reach syslog/journal AND stderr, so cron mail sees
# failures on hosts with an MTA. Without it a stuck load is silent.
log() {
    local level=$1; shift
    logger -s -t pping2-load -p "daemon.$level" -- "$*"
}

[ -r /etc/default/pping2 ] && . /etc/default/pping2

# tr ' ' '\t' below assumes no spaces inside fields. Holds for current
# -a/-e formats; a space-bearing field would need an awk/perl reformatter.

LOGFILE="${PPING_LOGFILE:-/var/log/pping2/pping2.log}"
LOADFILE="${LOGFILE}.load"
TABLE="${PPING_TABLE:-pping_flows}"
INGEST="${PPING_INGEST:-clickhouse-client}"

# Single-instance guard. Cron fires this every minute; without the lock a slow
# or stuck ingest (CH briefly unreachable, a stalled upload) lets each tick
# stack another loader, and they pile up until the sensors and the CH server
# mutually starve — none finishes, the .load never drains, and the live log
# grows unbounded. flock -n: if a prior run still holds the lock, skip this
# tick rather than queue behind it (a blocking wait would just re-stack).
LOCKFILE="${PPING_LOCKFILE:-/run/pping2-load.lock}"
exec 9>"$LOCKFILE"
flock -n 9 || { log info "another pping2-load holds $LOCKFILE; skipping this run"; exit 0; }

ingest_via_clickhouse_client() {
    tr ' ' '\t' < "$LOADFILE" \
      | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"
}

ingest_via_curl() {
    : "${CH_URL:?CH_URL not set in /etc/default/pping2 (required when PPING_INGEST=curl)}"
    local full_table="${CH_DATABASE:+${CH_DATABASE}.}${TABLE}"
    local auth_arg=()
    [ -n "${CH_AUTH:-}" ] && auth_arg=(-u "$CH_AUTH")
    # --speed-limit/--speed-time abort a transfer stalled below 1 B/s for
    # PPING_CURL_STALL_TIME seconds. curl otherwise has no transfer timeout, so
    # a stalled upload (server wedged mid-body) hangs forever — the failure that
    # stacked 66 half-sent inserts after a CH outage. The clickhouse-client path
    # needs no equivalent: its send/receive_timeout already defaults to 300s.
    {
        echo "INSERT INTO ${full_table} FORMAT TabSeparated"
        tr ' ' '\t' < "$LOADFILE"
    } | curl -sS -f --speed-limit 1 --speed-time "${PPING_CURL_STALL_TIME:-60}" \
        "${auth_arg[@]}" ${CH_CURL_OPTS:-} "$CH_URL/" --data-binary @-
}

case "$INGEST" in
    clickhouse-client) ingest_fn=ingest_via_clickhouse_client ;;
    curl)              ingest_fn=ingest_via_curl ;;
    *)
        log err "unknown PPING_INGEST='$INGEST' (expected 'clickhouse-client' or 'curl')"
        exit 1
        ;;
esac

# Route the ingest tool's stderr through logger so CH/curl errors reach
# syslog/journal. Process substitution requires bash (shebang mandates it).
ingest() {
    "$ingest_fn" 2> >(logger -s -t pping2-load -p daemon.err)
}

# Retry a $LOADFILE left by a previous failed ingest (e.g. CH unreachable).
# Checked before LOGFILE so a quiet pping2 still retries the stuck file.
if [ -f "$LOADFILE" ]; then
    log warning "$LOADFILE present from previous run; retrying ingest"
    if ingest; then
        rm "$LOADFILE"
    else
        log err "$INGEST retry of $LOADFILE failed; preserving for next run"
        exit 1
    fi
fi

[ -s "$LOGFILE" ] || exit 0    # nothing new to load (file missing or empty); silent — normal case

mv "$LOGFILE" "$LOADFILE"
if ! systemctl reload pping2.service; then
    log err "systemctl reload pping2 failed; pping2 is still writing to $LOADFILE — aborting load to preserve data"
    exit 1
fi

# Fence against pping2's block-buffered stdout. `systemctl reload` only
# sends SIGHUP; pping2 reopens on its next packet-loop iteration, fflush()ing
# its buffer tail to $LOADFILE (old inode) *before* open()ing the fresh
# $LOGFILE. printf writes whole records, so that flush lands on a record
# boundary — $LOGFILE reappearing means $LOADFILE is fully flushed. Ingest
# earlier and the tail is a partial buffer cut mid-record; ClickHouse rejects
# the whole batch: "Cannot parse input: expected '\t' at end of stream".
# Wait up to ~3s (first check before any sleep); an idle node has no torn
# tail anyway and just retries next run.
reopened=false
for _ in $(seq 1 6); do
    [ -e "$LOGFILE" ] && { reopened=true; break; }
    sleep 0.5
done
if [ "$reopened" != true ]; then
    log err "pping2 did not reopen $LOGFILE within 3s; $LOADFILE may be mid-flush — preserving for next run"
    exit 1
fi

if ingest; then
    rm "$LOADFILE"
else
    log err "$INGEST ingest failed; preserving $LOADFILE for next run"
    exit 1
fi
