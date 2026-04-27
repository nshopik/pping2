# Sending pping output to ClickHouse

pping machine-readable output (`-m` flag) writes space-separated lines to stdout:

```
unix_timestamp.usec rtt_sec minRTT_sec fBytes dBytes pBytes srcIP sport dstIP dport
```

The following options transfer that stream into ClickHouse, assuming the table schema is already prepared.

---

## 1. Direct pipe into `clickhouse-client` (simplest)

pping outputs space-separated; ClickHouse's `TSV` format expects tabs. Bridge with `tr`:

```sh
sudo ./pping -m -i eth0 | tr ' ' '\t' | clickhouse-client \
  --query="INSERT INTO pping_data FORMAT TSV"
```

Downside: no buffering, no retry on ClickHouse downtime — if the insert pipe breaks, data is lost.

---

## 2. Vector (recommended for production)

[Vector](https://vector.dev/) is purpose-built for this: reads from stdin, parses custom formats, buffers to disk, and writes to ClickHouse natively with retries.

```sh
sudo ./pping -m -i eth0 | vector --config vector.toml
```

Config would use a `stdin` source → `regex_parser` transform → `clickhouse` sink. Handles backpressure and reconnection automatically.

---

## 3. Intermediate file + batch load

Write to a rolling log file, load periodically:

```sh
sudo ./pping -m -i eth0 >> /var/log/pping.log

# cron: every minute
cat /var/log/pping.log | tr ' ' '\t' | clickhouse-client \
  --query="INSERT INTO pping_data FORMAT TSV" && > /var/log/pping.log
```

Simple, but file rotation and atomicity need care to avoid duplicates or data loss.

---

## 4. Modify pping to output to ClickHouse directly

Add the [ClickHouse HTTP API](https://clickhouse.com/docs/en/interfaces/http) call inside `pping.cpp`, POSTing batches of rows. More invasive but removes the pipeline dependency entirely.

---

## Recommendation

For a dev/one-off setup, option 1 is fine. For production where data loss matters, **Vector** is the least-friction path — it handles the space→tab conversion, buffering, and ClickHouse retries with a small config file and no code changes to pping.
