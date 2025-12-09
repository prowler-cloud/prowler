# Query Performance Guide

## Overview

This guide explains how to validate query performance when developing new endpoints or modifying existing ones. **This is part of the development process**, not a separate task—just like writing unit tests.

The goal is simple: ensure PostgreSQL uses indexes correctly. You don't need millions of records or complex stress testing setups. With 2-3 tenants and 2-3 scans, the query planner has enough information to decide whether to use indexes.

## When to Validate

You **must** run `EXPLAIN ANALYZE` when:

- Creating a new endpoint that queries the database
- Modifying an existing query (adding filters, joins, or sorting)
- Adding new indexes
- Working on performance-critical endpoints (overviews, findings, resources)

## How to Run EXPLAIN ANALYZE

### 1. Get Your Query

If you're using Django ORM, you can print the raw SQL:

```python
from api.models import Finding

queryset = Finding.objects.filter(tenant_id=tenant_id, status="FAIL")
print(queryset.query)
```

Or in Django shell:

```bash
cd api/src/backend
python manage.py shell
```

```python
from django.db import connection
from api.models import Finding

# Execute your queryset
qs = Finding.objects.filter(status="FAIL")[:10]
list(qs)  # Force evaluation

# Print the last query
print(connection.queries[-1]['sql'])
```

### 2. Run EXPLAIN ANALYZE

Connect to PostgreSQL and run:

```sql
EXPLAIN ANALYZE <your_query>;
```

Or with more details:

```sql
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) <your_query>;
```

### 3. Interpret the Results

#### Good Signs (Index is being used)

```
Index Scan using findings_tenant_status_idx on findings
  Index Cond: ((tenant_id = '...'::uuid) AND (status = 'FAIL'))
  Rows Removed by Filter: 0
  Actual Rows: 150
  Planning Time: 0.5 ms
  Execution Time: 2.3 ms
```

#### Bad Signs (Sequential scan - no index)

```
Seq Scan on findings
  Filter: ((tenant_id = '...'::uuid) AND (status = 'FAIL'))
  Rows Removed by Filter: 999850
  Actual Rows: 150
  Planning Time: 0.3 ms
  Execution Time: 450.2 ms
```

## Quick Reference: What to Look For

| What You See | Meaning | Action |
|--------------|---------|--------|
| `Index Scan` | Index is being used | Good, no action needed |
| `Index Only Scan` | Even better - data comes from index only | Good, no action needed |
| `Bitmap Index Scan` | Index used, results combined | Usually fine |
| `Seq Scan` on large tables | Full table scan, no index | **Needs investigation** |
| `Rows Removed by Filter: <high number>` | Fetching too many rows | **Query or index issue** |
| High `Execution Time` | Query is slow | **Needs optimization** |

## Common Issues and Fixes

### 1. Missing Index

**Problem:** `Seq Scan` on a filtered column

```sql
-- Bad: No index on status
EXPLAIN ANALYZE SELECT * FROM findings WHERE status = 'FAIL';
-- Shows: Seq Scan on findings
```

**Fix:** Add an index

```python
# In your model
class Meta:
    indexes = [
        models.Index(fields=['status'], name='findings_status_idx'),
    ]
```

### 2. Index Not Used Due to Type Mismatch

**Problem:** Index exists but PostgreSQL doesn't use it

```sql
-- If tenant_id is UUID but you're passing a string without cast
WHERE tenant_id = 'some-uuid-string'
```

**Fix:** Ensure proper type casting in your queries

### 3. Index Not Used Due to Function Call

**Problem:** Wrapping column in a function prevents index usage

```sql
-- Bad: Index on inserted_at won't be used
WHERE DATE(inserted_at) = '2024-01-01'

-- Good: Use range instead
WHERE inserted_at >= '2024-01-01' AND inserted_at < '2024-01-02'
```

### 4. Wrong Index for Sorting

**Problem:** Query is sorted but index doesn't match sort order

```sql
-- If you have ORDER BY inserted_at DESC
-- You need an index with DESC or PostgreSQL will sort in memory
```

**Fix:** Create index with matching sort order

```python
class Meta:
    indexes = [
        models.Index(fields=['-inserted_at'], name='findings_inserted_desc_idx'),
    ]
```

### 5. Composite Index Column Order

**Problem:** Index exists but columns are in wrong order

```sql
-- Index on (tenant_id, scan_id)
-- This query WON'T use the index efficiently:
WHERE scan_id = '...'

-- This query WILL use the index:
WHERE tenant_id = '...' AND scan_id = '...'
```

**Rule:** The leftmost columns in a composite index must be in your WHERE clause.

## RLS (Row Level Security) Considerations

Prowler uses Row Level Security. When analyzing queries, remember:

1. RLS policies add implicit `WHERE tenant_id = current_tenant()` to queries
2. Always test with RLS enabled (how it runs in production)
3. Ensure `tenant_id` is the first column in composite indexes

```python
# Use rls_transaction context manager for testing
from api.db_utils import rls_transaction

with rls_transaction(tenant_id):
    qs = Finding.objects.filter(status="FAIL")
    # Now run EXPLAIN ANALYZE on this query
```

## Performance Checklist for PRs

Before submitting a PR that adds or modifies database queries:

- [ ] Ran `EXPLAIN ANALYZE` on new/modified queries
- [ ] Verified indexes are being used (no unexpected `Seq Scan`)
- [ ] Checked `Rows Removed by Filter` is reasonable
- [ ] Tested with RLS enabled
- [ ] For critical endpoints: documented the query plan in the PR

## Minimum Test Data

You don't need millions of records. The query planner makes decisions based on:

- Table statistics (run `ANALYZE` if needed)
- Index definitions
- Query structure

**Minimum setup for validation:**
- 2-3 tenants
- 2-3 providers per tenant
- 2-3 scans per provider
- A few hundred findings/resources

This is enough for PostgreSQL to decide whether to use indexes.

## Useful Commands

### Update Table Statistics

```sql
ANALYZE findings;
ANALYZE resources;
```

### See Existing Indexes

```sql
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'findings';
```

### See Index Usage Stats

```sql
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE tablename = 'findings'
ORDER BY idx_scan DESC;
```

### Check Table Size

```sql
SELECT
    relname as table_name,
    pg_size_pretty(pg_total_relation_size(relid)) as total_size
FROM pg_catalog.pg_statio_user_tables
WHERE relname IN ('findings', 'resources', 'scans')
ORDER BY pg_total_relation_size(relid) DESC;
```

## Further Reading

- [PostgreSQL EXPLAIN Documentation](https://www.postgresql.org/docs/current/sql-explain.html)
- [Using EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html)
- [Index Types in PostgreSQL](https://www.postgresql.org/docs/current/indexes-types.html)
- [Prowler Partitions Documentation](./partitions.md)
