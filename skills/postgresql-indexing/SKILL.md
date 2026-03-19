---
name: postgresql-indexing
description: >
  PostgreSQL indexing best practices for Prowler: index design, partial indexes, partitioned table
  indexing, EXPLAIN ANALYZE validation, concurrent operations, monitoring, and maintenance.
  Trigger: When creating or modifying PostgreSQL indexes, analyzing query performance with EXPLAIN,
  debugging slow queries, reviewing index usage statistics, reindexing, dropping indexes, or working
  with partitioned table indexes. Also trigger when discussing index strategies, partial indexes,
  or index maintenance operations like VACUUM or ANALYZE.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [api]
  auto_invoke:
    - "Creating or modifying PostgreSQL indexes"
    - "Analyzing query performance with EXPLAIN"
    - "Debugging slow queries or missing indexes"
    - "Dropping or reindexing PostgreSQL indexes"
allowed-tools: Read, Grep, Glob, Bash
---

## When to use

- Creating or modifying PostgreSQL indexes
- Analyzing query plans with `EXPLAIN`
- Debugging slow queries or missing index usage
- Dropping, reindexing, or validating indexes
- Working with indexes on partitioned tables (findings, resource_finding_mappings)
- Running VACUUM or ANALYZE after index changes

## Index design

### Partial indexes: constant columns go in WHERE, not in the key

When a column has a fixed value for the query (e.g., `state = 'completed'`), put it in the `WHERE` clause of the index, not in the indexed columns. Otherwise the planner cannot exploit the ordering of the other columns.

```sql
-- Bad: state in the key wastes space and breaks ordering
CREATE INDEX idx_scans_tenant_state ON scans (tenant_id, state, inserted_at DESC);

-- Good: state as a filter, planner uses tenant_id + inserted_at ordering
CREATE INDEX idx_scans_tenant_ins_completed ON scans (tenant_id, inserted_at DESC)
    WHERE state = 'completed';
```

### Column order matters

Put high-selectivity columns first (columns that filter out the most rows). For composite indexes, the leftmost column must appear in the query's WHERE clause for the index to be used.

## Validating index effectiveness

### Always EXPLAIN (ANALYZE, BUFFERS) after adding indexes

Never assume an index is being used. Run `EXPLAIN (ANALYZE, BUFFERS)` to confirm.

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM users
WHERE email = 'user@example.com';
```

Use [Postgres EXPLAIN Visualizer (pev)](https://tatiyants.com/pev/) to visualize query plans and identify bottlenecks.

### Force index usage for testing

The planner may choose a sequential scan on small datasets. Toggle `enable_seqscan = off` to confirm the index path works, then re-enable it.

```sql
SET enable_seqscan = off;

EXPLAIN (ANALYZE, BUFFERS)
SELECT DISTINCT ON (provider_id) provider_id
FROM scans
WHERE tenant_id = '95383b24-da01-44b5-a713-0d9920d554db'
  AND state = 'completed'
ORDER BY provider_id, inserted_at DESC;

SET enable_seqscan = on;  -- always re-enable after testing
```

This is for validation only. Never leave `enable_seqscan = off` in production.

## Over-indexing

Every extra index has three costs that compound:

1. **Write overhead.** Every INSERT and UPDATE must maintain all indexes. Extra indexes also kill HOT (Heap-Only-Tuple) updates, which normally skip index maintenance when unindexed columns change.

2. **Planning time.** The planner evaluates more execution paths per index. On simple OLTP queries, planning time can exceed execution time by 4x when index count is high.

3. **Lock contention (fastpath limit).** PostgreSQL uses a fast path for the first 16 locks per backend. After 16 relations (table + its indexes), it falls back to slower LWLock mechanisms. At high QPS (100+), this causes `LockManager` wait events.

Rules:
- Drop unused and redundant indexes regularly
- Be especially careful with partitioned tables (each partition multiplies the index count)
- Use prepared statements to reduce planning overhead when index count is high

## Finding redundant indexes

Two indexes are redundant when:
- They have the same columns in the same order (duplicates)
- One is a prefix of the other: index `(a)` is redundant to `(a, b)`, but NOT to `(b, a)`

Column order matters. For partial indexes, the WHERE clause must also match.

```sql
-- Quick check: find indexes that share a leading column on the same table
SELECT
    a.indrelid::regclass AS table_name,
    a.indexrelid::regclass AS index_a,
    b.indexrelid::regclass AS index_b,
    pg_size_pretty(pg_relation_size(a.indexrelid)) AS size_a,
    pg_size_pretty(pg_relation_size(b.indexrelid)) AS size_b
FROM pg_index a
JOIN pg_index b ON a.indrelid = b.indrelid
    AND a.indexrelid != b.indexrelid
    AND a.indkey::text = (
        SELECT string_agg(x::text, ' ')
        FROM unnest(b.indkey[:array_length(a.indkey, 1)]) AS x
    )
WHERE NOT a.indisunique;
```

Before dropping: verify on all workload nodes (primary + replicas), use `DROP INDEX CONCURRENTLY`, and monitor for plan regressions.

## Monitoring index usage

### Identify unused indexes

Query `pg_stat_all_indexes` to find indexes that are never or rarely scanned:

```sql
SELECT
    idxstat.schemaname AS schema_name,
    idxstat.relname AS table_name,
    idxstat.indexrelname AS index_name,
    idxstat.idx_scan AS index_scans_count,
    idxstat.last_idx_scan AS last_idx_scan_timestamp,
    pg_size_pretty(pg_relation_size(idxstat.indexrelid)) AS index_size
FROM pg_stat_all_indexes AS idxstat
JOIN pg_index i ON idxstat.indexrelid = i.indexrelid
WHERE idxstat.schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND NOT i.indisunique
ORDER BY idxstat.idx_scan ASC, idxstat.last_idx_scan ASC;
```

Indexes with `idx_scan = 0` and no recent `last_idx_scan` are candidates for removal.

Before dropping, verify:
- Stats haven't been reset recently (check `stats_reset` in `pg_stat_database`)
- Stats cover at least 1 month of production traffic
- All workload nodes (primary + replicas) have been checked
- The index isn't used by a periodic job that runs infrequently

```sql
-- Check when stats were last reset
SELECT stats_reset, age(now(), stats_reset)
FROM pg_stat_database
WHERE datname = current_database();
```

### Monitor index creation progress

Do not assume index creation succeeded. Use `pg_stat_progress_create_index` (Postgres 12+) to watch progress live:

```sql
SELECT * FROM pg_stat_progress_create_index;
```

In psql, use `\watch 5` to refresh every 5 seconds for a live dashboard view. `CREATE INDEX CONCURRENTLY` and `REINDEX CONCURRENTLY` have more phases than standard operations: monitor for blocking sessions and wait events.

### Validate index integrity

Check for invalid indexes regularly:

```sql
SELECT c.relname AS index_name, i.indisvalid
FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
WHERE i.indisvalid = false;
```

Invalid indexes are ignored by the planner. They waste space and cause inconsistent query performance, especially on partitioned tables where some partitions may have valid indexes and others do not.

## Concurrent operations

### Always use CONCURRENTLY in production

Never create or drop indexes without `CONCURRENTLY` on live tables. Without it, the operation holds a lock that blocks all writes.

```sql
-- Create
CREATE INDEX CONCURRENTLY IF NOT EXISTS index_name ON table_name (column_name);

-- Drop
DROP INDEX CONCURRENTLY IF EXISTS index_name;
```

`DROP INDEX CONCURRENTLY` cannot run inside a transaction block.

### Always use IF NOT EXISTS / IF EXISTS

Makes scripts idempotent. Safe to re-run without errors from duplicate or missing indexes.

### Concurrent indexing can fail silently

`CREATE INDEX CONCURRENTLY` can fail without raising an error. The result is an invalid index that the planner ignores. This is particularly dangerous on partitioned tables: some partitions get valid indexes, others don't, causing inconsistent query performance.

After any concurrent index creation, always validate:

```sql
SELECT c.relname, i.indisvalid
FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
WHERE c.relname LIKE '%your_index_name%';
```

## Reindexing invalid indexes

Rebuild invalid indexes without locking writes:

```sql
REINDEX INDEX CONCURRENTLY index_name;
```

### Understanding _ccnew and _ccold artifacts

When `CREATE INDEX CONCURRENTLY` or `REINDEX INDEX CONCURRENTLY` is interrupted, temporary indexes may remain:

| Suffix | Meaning | Action |
|--------|---------|--------|
| `_ccnew` | New index being built, incomplete | Drop it and retry `REINDEX CONCURRENTLY` |
| `_ccold` | Old index being replaced, rebuild succeeded | Safe to drop |

```sql
-- Example: both original and temp are invalid
-- users_emails_2019       btree (col) INVALID
-- users_emails_2019_ccnew btree (col) INVALID

-- Drop the failed new one, then retry
DROP INDEX CONCURRENTLY IF EXISTS users_emails_2019_ccnew;
REINDEX INDEX CONCURRENTLY users_emails_2019;
```

These leftovers clutter the schema, confuse developers, and waste disk space. Clean them up.

## Indexing partitioned tables

### Do NOT use ALTER INDEX ATTACH PARTITION

As stated in PostgreSQL documentation, `ALTER INDEX ... ATTACH PARTITION` prevents dropping malfunctioning or non-performant indexes from individual partitions. An attached index cannot be dropped by itself and is automatically dropped if its parent index is dropped.

This removes the ability to manage indexes per-partition, which we need for:
- Dropping broken indexes on specific partitions
- Skipping indexes on old partitions to save storage
- Rebuilding indexes on individual partitions without affecting others

### Correct approach: create on partitions, then on parent

1. Create the index on each child partition concurrently:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_child_partition
    ON child_partition (column_name);
```

2. Create the index on the parent table (metadata-only, fast):

```sql
CREATE INDEX IF NOT EXISTS idx_parent
    ON parent_table (column_name);
```

PostgreSQL will automatically recognize partition-level indexes as part of the parent index definition when the index names and definitions match.

### Prioritize active partitions

For time-based partitions (findings uses monthly partitions):

- Create indexes on recent/current partitions where data is actively queried
- Skip older partitions that are rarely accessed
- The `all_partitions=False` default in `create_index_on_partitions` handles this automatically

## Index maintenance and bloat

Over time, B-tree indexes accumulate bloat from updates and deletes. VACUUM reclaims heap space but does NOT rebalance B-tree pages. Periodic reindexing is necessary for heavily updated tables.

### Detecting bloat

Indexes with estimated bloat above 50% are candidates for `REINDEX CONCURRENTLY`. Check bloat with tools like `pgstattuple` or bloat estimation queries.

### Reducing bloat buildup

Three things slow degradation:
1. **Upgrade to PostgreSQL 14+** for B-tree deduplication and bottom-up deletion
2. **Maximize HOT updates** by not indexing frequently-updated columns
3. **Tune autovacuum** to run more aggressively on high-churn tables

### Rebuilding many indexes without deadlocks

If you rebuild two indexes on the same table in parallel, PostgreSQL detects a deadlock and kills one session. To rebuild many indexes across multiple sessions safely, assign all indexes for a given table to the same session:

```sql
\set NUMBER_OF_SESSIONS 10

SELECT
    format('%I.%I', n.nspname, c.relname) AS table_fqn,
    format('%I.%I', n.nspname, i.relname) AS index_fqn,
    mod(
        hashtext(format('%I.%I', n.nspname, c.relname)) & 2147483647,
        :NUMBER_OF_SESSIONS
    ) AS session_id
FROM pg_index idx
JOIN pg_class c ON idx.indrelid = c.oid
JOIN pg_class i ON idx.indexrelid = i.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname NOT IN ('pg_catalog', 'pg_toast', 'information_schema')
ORDER BY table_fqn, index_fqn;
```

Then run each session's indexes in a separate `REINDEX INDEX CONCURRENTLY` call. Set `NUMBER_OF_SESSIONS` based on `max_parallel_maintenance_workers` and available I/O.

## Dropping indexes

### Post-drop maintenance

After dropping an index, run VACUUM and ANALYZE to reclaim space and update planner statistics:

```sql
-- Full vacuum + analyze (can be heavy on large tables)
VACUUM (ANALYZE) your_table;

-- Lightweight alternative for huge tables: just update statistics
ANALYZE your_table;
```

## Commands

```sql
-- Validate query uses an index
EXPLAIN (ANALYZE, BUFFERS) SELECT ...;

-- Check index creation progress
SELECT * FROM pg_stat_progress_create_index;

-- Find invalid indexes
SELECT c.relname, i.indisvalid
FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
WHERE i.indisvalid = false;

-- Find unused indexes
SELECT relname, indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid))
FROM pg_stat_all_indexes
WHERE schemaname = 'public' AND idx_scan = 0;

-- Create index safely
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_name ON table (columns);

-- Drop index safely
DROP INDEX CONCURRENTLY IF EXISTS idx_name;

-- Rebuild invalid index
REINDEX INDEX CONCURRENTLY idx_name;

-- Post-drop maintenance
VACUUM (ANALYZE) table_name;
```

## Context7 lookups

**Prerequisite:** Install Context7 MCP server for up-to-date documentation lookup.

| Library | Context7 ID | Use for |
|---------|-------------|---------|
| PostgreSQL | `/websites/postgresql_org_docs_current` | Index types, EXPLAIN, partitioned table indexing, REINDEX |

**Example queries:**
```
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="CREATE INDEX CONCURRENTLY partitioned table")
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="EXPLAIN ANALYZE BUFFERS query plan")
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="partial index WHERE clause")
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="REINDEX CONCURRENTLY invalid index")
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="pg_stat_all_indexes monitoring")
```

> **Note:** Use `mcp_context7_resolve-library-id` first if you need to find the correct library ID.

## Resources

- **EXPLAIN Visualizer**: [pev](https://tatiyants.com/pev/)
