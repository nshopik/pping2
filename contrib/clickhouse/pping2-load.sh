#!/bin/bash
# Batch-load pping2's log file into ClickHouse. Driven by /etc/cron.d/pping2-load.
#
# Rotation is fast and zero-copy: mv is atomic at the dirent level (same fs);
# pping2 holds an O_APPEND fd on the original inode (now at $LOADFILE). We
# then `systemctl reload pping2` which sends SIGHUP through to pping2, and it
# reopens its --logfile path — which now points to a fresh empty file. Old
# data is in $LOADFILE; new data accumulates in $LOGFILE.
#
# Two ingest paths: clickhouse-client (default) and curl (HTTP interface).
# See /etc/default/pping2 for configuration.
set -euo pipefail

# All diagnostic output goes through `logger -s` so it lands in
# syslog/journal AND on stderr (the latter reaches cron mail when an MTA
# is configured). Without this, a misconfigured CH host or a stuck
# .load file produces no visible signal on systems with no MTA — the
# common "everything looks fine but no data is loading" failure mode.
log() {
    local level=$1; shift
    logger -s -t pping2-load -p "daemon.$level" -- "$*"
}

[ -r /etc/default/pping2 ] && . /etc/default/pping2

# tr ' ' '\t' below assumes pping2's space-separated output has no spaces
# inside fields. True for the current `-a` / `-e` formats (numerics, IPs,
# RFC-bound FQDNs, single-char tags). If pping2 ever gains a field that
# can contain spaces, this loader needs an awk/perl reformatter.

LOGFILE="${PPING_LOGFILE:-/var/log/pping2/pping2.log}"
LOADFILE="${LOGFILE}.load"
TABLE="${PPING_TABLE:-pping_flows}"
INGEST="${PPING_INGEST:-clickhouse-client}"

ingest_via_clickhouse_client() {
    tr ' ' '\t' < "$LOADFILE" \
      | clickhouse-client $CH_ARGS --query="INSERT INTO ${TABLE} FORMAT TSV"
}

ingest_via_curl() {
    : "${CH_URL:?CH_URL not set in /etc/default/pping2 (required when PPING_INGEST=curl)}"
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
ingest() {
    "$ingest_fn" 2> >(logger -s -t pping2-load -p daemon.err)
}

# Previous run's ingest failed and left $LOADFILE behind (e.g. CH was
# unreachable). Retry it now instead of blocking forever until an operator
# steps in — checked before LOGFILE so even a quiet pping2 (no new rows)
# still retries the stuck file once a minute.
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

# Fence the rotation against pping2's block-buffered stdout. `systemctl
# reload` only sends SIGHUP and returns; pping2 reopens on its next
# packet-loop iteration, and reopenLogfile() fflush()es the tail of its
# buffer to $LOADFILE (the old inode) *before* open()ing the fresh
# O_CREAT'd $LOGFILE. Since printf writes whole records, that fflush lands
# on a record boundary. So $LOGFILE reappearing is the signal that
# $LOADFILE is fully flushed and newline-terminated. Ingest before that and
# the tail is a partial 4KB-buffer flush cut mid-record — ClickHouse then
# rejects the whole batch with "Cannot parse input: expected '\t' at end of
# stream". Wait up to ~3s: a busy node reopens in ms (the first check runs
# before any sleep), and a truly idle node has no new data to tear anyway —
# its $LOADFILE is just retried next run.
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
