# Sending pping output to ClickHouse

pping machine-readable output (`-m` flag) writes space-separated lines to stdout:

```
unix_timestamp.usec rtt_sec minRTT_sec fBytes dBytes pBytes srcIP sport dstIP dport
```

The following options transfer that stream into ClickHouse, assuming the table schema is already prepared.

---

## 1. Vector (recommended for production)

[Vector](https://vector.dev/) is purpose-built for this: reads from stdin, parses custom formats, buffers to disk, and writes to ClickHouse natively with retries.

```sh
sudo ./pping -m -i eth0 | vector --config vector.toml
```

Config would use a `stdin` source → `regex_parser` transform → `clickhouse` sink. Handles backpressure and reconnection automatically.

---

## 2. Intermediate file + batch load

Write to a rolling log file, load periodically:

```sh
sudo ./pping -m -i eth0 >> /var/log/pping.log

# cron: every minute
mv /var/log/pping.log /var/log/pping.load.log
cat /var/log/pping.load.log | tr ' ' '\t' | clickhouse-client \
  --query="INSERT INTO pping_data FORMAT TSV" && rm /var/log/pping.load.log
```

`mv` is atomic — pping continues appending to a new `/var/log/pping.log` immediately after the rename, so no lines are lost while the load is running. The load file is only deleted on successful insert; if ClickHouse is unavailable, it stays on disk for the next run.

---

## Recommendation

**Vector** is the preferred path — it handles buffering, retries, and backpressure automatically with no code changes to pping. The file + batch approach works as a simpler fallback but requires careful handling of rotation to avoid duplicates or data loss.
