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
