-- Write-only ClickHouse user for the pping2-load.sh loader.
--
-- Grants INSERT on pping_flows only — no SELECT, no DDL, no access to any
-- other table or database. Apply after schema.sql, against the same
-- database CH_ARGS/--database points at:
--   clickhouse-client < ingest-user.sql
-- Or for a non-default database:
--   clickhouse-client --database metrics --multiquery < ingest-user.sql
--
-- Change the password before running.

CREATE USER IF NOT EXISTS pping2 IDENTIFIED WITH sha256_password BY 'CHANGE_ME';

GRANT INSERT ON pping_flows TO pping2;
