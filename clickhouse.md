# Sending pping output to ClickHouse

This is the worked end-to-end example for the most common pping deployment:
capture on a host, batch-load aggregated rows into ClickHouse every minute.
Everything below is automated by the Makefile install targets — you only edit
one config file and run two commands.

## Quickstart

On a Debian-flavored host with pping built and `clickhouse-client` available:

```sh
sudo make install-all
sudo $EDITOR /etc/default/pping        # set PPING_IFACE and CH_ARGS
clickhouse-client < /usr/local/share/pping/schema.sql
sudo systemctl enable --now pping
```

That's the entire setup. Within a minute the cron loader picks up
`/var/log/pping.log` and inserts into the `pping_flows` table.

## What got installed

| Path | Source | Purpose |
| --- | --- | --- |
| `/usr/local/bin/pping` | binary | the daemon |
| `/etc/systemd/system/pping.service` | `contrib/systemd/` | systemd unit; `ExecReload` sends SIGHUP for log rotation |
| `/etc/default/pping` | `contrib/systemd/pping.default` | the **only** file you edit; sourced by both daemon and loader |
| `/usr/local/bin/pping-load.sh` | `contrib/clickhouse/` | cron-driven batch loader |
| `/etc/cron.d/pping-load` | `contrib/clickhouse/` | runs the loader every minute |
| `/usr/local/share/pping/schema.sql` | `contrib/clickhouse/` | reference schema (apply manually) |

`make uninstall-all` removes everything except `/etc/default/pping` (your
edited config) and `/var/log/pping.log` (your data).

## Configuring `/etc/default/pping`

Three settings you must touch, two you might:

```sh
PPING_IFACE=eth0                       # required; single interface only
PPING_FLAGS=-a                         # default: aggregate mode (recommended)
PPING_LOGFILE=/var/log/pping.log       # default; rotation pivots on this path
PPING_TABLE=pping_flows                # default; only change if you renamed
CH_ARGS="--host ch.internal --user pping --password=hunter2 --database metrics"
```

**Multi-interface:** not supported in v1. Each unit instance monitors a
single interface; running multiple capture points on one host means
multiple unit instances (manual today). Proper multi-interface support
will land alongside a per-row `interface` column in a future release.

**`CH_ARGS`** is passed unquoted to `clickhouse-client`, so multi-flag values
like the example above just work. Values must not contain internal spaces;
for passwords with spaces use a clickhouse-client config file.

## How rotation works

The loader runs every minute via cron. Each cycle:

1. `mv /var/log/pping.log /var/log/pping.log.load` — atomic at the dirent
   level, zero-copy. pping's open fd still points at the renamed inode.
2. `systemctl reload pping.service` — sends SIGHUP through the supervisor
   to all pping children. They reopen `--logfile` at its original path,
   creating a fresh `/var/log/pping.log` (new inode) for new rows.
3. `tr ' ' '\t' < /var/log/pping.log.load | clickhouse-client INSERT...`
   — old rows go into ClickHouse.
4. On success, `rm /var/log/pping.log.load`. On failure, the `.load` file
   stays on disk and the next minute's run skips (preserving the data) until
   the next ingest succeeds.

This is fast even on busy hosts — no file copying, no truncation race. The
only data lost across a rotation is whatever pping wrote in the microsecond
window between `mv` and the SIGHUP being delivered.

## Tuning the load

- `PPING_FLAGS=-a --flowMaxAge=900` halves the per-flow window from the 1800s
  default — emit closed flows + 15-minute snapshots for long-lived flows.
  See README's "Output formats" for the full `-a` semantics.
- The cron loader runs every minute. If ClickHouse is unreachable, the
  `.load` stays on disk and the next minute's run keeps appending to a fresh
  `pping.log` — no data loss, just a bigger batch on the next success.
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

## Alternative: Vector

If you already operate [Vector](https://vector.dev/), you can drop the cron
loader entirely:

```sh
sudo /usr/local/bin/pping $PPING_FLAGS -i $PPING_IFACE | vector --config vector.toml
```

Configure a `stdin` source → `regex_parser` transform (one regex per pping
output field) → `clickhouse` sink. Vector handles buffering, retries, and
backpressure on its own. Not recommended over the cron path for a fresh
deployment — it's only worth it if Vector is already part of your stack.
