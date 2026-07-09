# Sending pping2 output to ClickHouse

This is the worked end-to-end example for the most common pping2 deployment:
capture on a host, batch-load aggregated rows into ClickHouse every minute.
Everything below is automated by the Makefile install targets — you only edit
one config file and run two commands.

## Quickstart

On a Debian-flavored host with pping2 built and `clickhouse-client` available:

```sh
sudo make install-all
sudo $EDITOR /etc/default/pping2        # set PPING_IFACE and CH_ARGS
clickhouse-client < /usr/local/share/pping2/schema.sql
clickhouse-client < /usr/local/share/pping2/ingest-user.sql   # edit password first
sudo systemctl enable --now pping2
```

That's the entire setup. Within a minute the cron loader picks up
`/var/log/pping2/pping2.log` and inserts into the `pping_flows` table.

## What got installed

| Path | Source | Purpose |
| --- | --- | --- |
| `/usr/local/bin/pping2` | binary | the daemon |
| `/etc/systemd/system/pping2.service` | `contrib/systemd/` | systemd unit; `ExecReload` sends SIGHUP for log rotation |
| `/etc/default/pping2` | `contrib/systemd/pping2.default` | the **only** file you edit; sourced by both daemon and loader |
| `/usr/local/bin/pping2-load.sh` | `contrib/clickhouse/` | cron-driven batch loader |
| `/etc/cron.d/pping2-load` | `contrib/clickhouse/` | runs the loader every minute |
| `/usr/local/share/pping2/schema.sql` | `contrib/clickhouse/` | reference schema (apply manually) |
| `/usr/local/share/pping2/ingest-user.sql` | `contrib/clickhouse/` | write-only loader user (apply manually) |
| `/var/log/pping2/` | `make install-systemd` | log dir, owned by `nobody` so the daemon can recreate the file on SIGHUP |

`make uninstall-all` removes everything except `/etc/default/pping2` (your
edited config) and `/var/log/pping2/pping2.log` (your data).

## Configuring `/etc/default/pping2`

Three settings you must touch, two you might:

```sh
PPING_IFACE=eth0                       # required; single interface only
PPING_FLAGS=-a                         # default: aggregate mode (recommended)
PPING_LOGFILE=/var/log/pping2/pping2.log # default; dir must be writable by `nobody`
PPING_TABLE=pping_flows                # default; only change if you renamed
PPING_INGEST=clickhouse-client         # or 'curl' — see below

# clickhouse-client mode:
CH_ARGS="--host ch.internal --user pping2 --password=hunter2 --database metrics"

# curl mode (alternative):
# CH_URL=https://ch.internal:8443
# CH_AUTH=pping:hunter2
# CH_DATABASE=metrics
```

**Multi-interface:** not supported. Tracked in `TODOS.md`.

**`CH_ARGS`** is passed unquoted to `clickhouse-client`, so multi-flag values
like the example above just work. Values must not contain internal spaces;
for passwords with spaces use a clickhouse-client config file.

## Choosing an ingest method

The loader supports two ingest paths, selected via `PPING_INGEST`:

**`clickhouse-client` (default).** Requires the `clickhouse-client` binary
on the capture host. Speaks ClickHouse's native TCP protocol — slightly
more efficient than HTTP and supports every server feature.

**`curl`.** Uses ClickHouse's HTTP interface. `curl` is preinstalled on
nearly every distro, so this path needs no extra packages on the capture
host. Particularly useful when the host is a minimal appliance or
container that doesn't otherwise touch ClickHouse tooling. Configure with
`CH_URL`, `CH_AUTH`, optional `CH_DATABASE`, and `CH_CURL_OPTS` for things
like `--cacert` or `--max-time`.

Both modes use the same loader cron entry, the same `mv` + `systemctl reload`
rotation, and the same `.load` file retry semantics on failure. Switch by
editing `/etc/default/pping2`; no service restart required (the loader
re-reads the env file every minute).

## How rotation works

`pping2-load.sh` rotates by `mv` — atomic at the dirent level, so pping2's
open fd stays valid on the renamed inode and no rows are lost. `systemctl
reload` then sends SIGHUP; pping2 reopens its `--logfile` path on the next
packet-loop tick, capped at libtins's 250ms pcap timeout. On ingest failure
the `.load` file persists; the next minute's run sees it at the top and
exits, preserving data until ClickHouse is reachable again.

## Tuning the load

- `PPING_FLAGS=-a --flowMaxAge=900` halves the per-flow window from the 1800s
  default — emit closed flows + 15-minute snapshots for long-lived flows.
  See README's "Output formats" for the full `-a` semantics.
- The cron loader runs every minute. If ClickHouse is unreachable, the
  `.load` stays on disk and the next minute's run keeps appending to a fresh
  `pping2.log` — no data loss, just a bigger batch on the next success.
- The shipped table TTL is 30 days
  (`TTL toDateTime(timestamp) + toIntervalDay(30)`). Adjust to taste.

## Schema reference

```sql
CREATE TABLE IF NOT EXISTS pping_flows
(
    `timestamp`  DateTime64(6),
    `min_rtt`    Float64,
    `n_samples`  UInt32,
    `src_ip`     String,
    `sport`      UInt16,
    `dst_ip`     String,
    `dport`      UInt16,
    `node`       LowCardinality(String),
    `tag`        LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (timestamp, src_ip, sport, dst_ip, dport)
TTL toDateTime(timestamp) + toIntervalDay(30);
```

| Column | Meaning |
| --- | --- |
| `timestamp` | flow's `last_tm` (last packet time) at emit |
| `min_rtt` | minimum RTT observed in this row's window, seconds |
| `n_samples` | RTT matches contributing to `min_rtt` (confidence signal) |
| `src_ip`/`sport`/`dst_ip`/`dport` | TCP 4-tuple |
| `node` | capture host's FQDN |
| `tag` | `t` (TCP-timestamp path) or `s` (SEQ/ACK path) |

`node` and `tag` are `LowCardinality(String)` — both have small distinct-value
sets and benefit from the dictionary encoding.

## Ingest user

`contrib/clickhouse/ingest-user.sql` creates a `pping2` user with `INSERT`
on `pping_flows` only — no `SELECT`, no DDL, no other table or database.
Edit the password before applying, then point `CH_ARGS`/`CH_AUTH` at it:

```sql
CREATE USER IF NOT EXISTS pping2 IDENTIFIED WITH sha256_password BY 'CHANGE_ME';
GRANT INSERT ON pping_flows TO pping2;
```

## Alternative: Vector

If you already operate [Vector](https://vector.dev/), you can drop the cron
loader entirely:

```sh
sudo /usr/local/bin/pping2 $PPING_FLAGS -i $PPING_IFACE | vector --config vector.toml
```

Configure a `stdin` source → `regex_parser` transform (one regex per pping2
output field) → `clickhouse` sink. Vector handles buffering, retries, and
backpressure on its own. Not recommended over the cron path for a fresh
deployment — it's only worth it if Vector is already part of your stack.
