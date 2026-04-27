# Deployment

Step-by-step guide to run pping and batch-ingest its output into ClickHouse using the intermediate file approach (option 2 from clickhouse.md).

## 1. Create ClickHouse table

IP addresses are stored as `String` to handle both IPv4 and IPv6 without separate columns.
`DateTime64(6)` stores capture time with microsecond precision.

```sql
CREATE TABLE IF NOT EXISTS pping_rtt
(
    `timestamp`  DateTime64(6),
    `rtt`        Float64,
    `min_rtt`    Float64,
    `f_bytes`    UInt64,
    `d_bytes`    UInt64,
    `p_bytes`    UInt64,
    `src_ip`     String,
    `sport`      UInt16,
    `dst_ip`     String,
    `dport`      UInt16,
    `node`       String
)
ENGINE = MergeTree
ORDER BY (timestamp, src_ip, sport, dst_ip, dport)
TTL toDateTime(timestamp) + toIntervalDay(30);
```

## 2. Run pping as a systemd service

Create `/etc/systemd/system/pping.service`:

```ini
[Unit]
Description=pping passive RTT monitor
After=network.target

[Service]
ExecStart=/usr/local/bin/pping -m -i eth0
StandardOutput=append:/var/log/pping.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now pping
```

## 3. Create batch load script

Create `/usr/local/bin/pping-load.sh`:

```sh
#!/bin/bash
set -euo pipefail

LOGFILE=/var/log/pping.log
LOADFILE=/var/log/pping.load.log
CH_TABLE=pping_rtt

[ -f "$LOGFILE" ]   || exit 0   # nothing new to load
[ ! -f "$LOADFILE" ] || exit 0   # previous load still in progress, keep accumulating in $LOGFILE

mv "$LOGFILE" "$LOADFILE"

tr ' ' '\t' < "$LOADFILE" \
  | clickhouse-client --query="INSERT INTO ${CH_TABLE} FORMAT TSV" \
  && rm "$LOADFILE"
```

```sh
chmod +x /usr/local/bin/pping-load.sh
```

## 4. Schedule the load via cron

Create `/etc/cron.d/pping-load`:

```
* * * * * root /usr/local/bin/pping-load.sh
```

The script runs every minute. If ClickHouse is unavailable the `.load.log` file is kept and retried on the next run. Successive failures accumulate data in the same file since `mv` won't overwrite an existing `.load.log`.
