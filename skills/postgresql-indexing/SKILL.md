---
name: postgresql-indexing
description: "Trigger: When designing, validating, dropping, or repairing PostgreSQL indexes, including EXPLAIN analysis and partitioned-table indexing. Enforces Prowler-safe index design, concurrent operations, and partition maintenance rules."
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

## Activation Contract

Use this skill when query performance or schema work depends on PostgreSQL index design, validation, integrity, or partition-aware maintenance.

## Hard Rules

- Put constant filters in partial-index `WHERE` clauses, not in the indexed key.
- Validate every proposed index with `EXPLAIN (ANALYZE, BUFFERS)`; never assume the planner will use it.
- On live tables, create, drop, and rebuild indexes with `CONCURRENTLY` and idempotent guards where possible.
- After `CREATE INDEX CONCURRENTLY`, always verify `indisvalid`; concurrent builds can leave unusable invalid indexes behind.
- Do not use `ALTER INDEX ... ATTACH PARTITION`; Prowler needs independent partition index control.
- For partitioned tables, build child-partition indexes first, then create the parent definition.
- Watch over-indexing: extra indexes increase write cost, planning cost, and lock pressure.
- After dropping indexes, refresh planner stats with `VACUUM (ANALYZE)` or at least `ANALYZE`.

## Decision Gates

| Question | Action |
|---|---|
| Query always filters on a fixed value like `state = 'completed'`? | Use a partial index with the constant in `WHERE`. |
| Planner still chooses a seq scan on a tiny dataset? | Toggle `enable_seqscan = off` only for validation, then turn it back on. |
| Creating or dropping on a live table? | Use `CONCURRENTLY`; avoid transaction wrappers that would invalidate the command. |
| Working on `findings` or another partitioned table? | Create matching indexes on children first, then register the parent index. |
| Index build succeeded syntactically but performance is still bad? | Check `pg_stat_progress_create_index`, `pg_index.indisvalid`, and redundant/unused index patterns. |
| Need to remove an index? | Confirm workload coverage, drop concurrently, then run post-drop maintenance. |

## Execution Steps

1. Start from the query shape: filters, ordering, distinct/grouping, and whether a partial predicate can shrink the index.
2. Choose column order by selectivity and leftmost-filter usage; avoid indexing frequently updated columns unless justified.
3. Run `EXPLAIN (ANALYZE, BUFFERS)` before and after, and use `enable_seqscan = off` only as a temporary proof that the index path is valid.
4. For production changes, use `CREATE INDEX CONCURRENTLY IF NOT EXISTS`, `DROP INDEX CONCURRENTLY IF EXISTS`, or `REINDEX INDEX CONCURRENTLY` as appropriate.
5. Validate the result with `pg_index.indisvalid`; if `_ccnew` or `_ccold` artifacts appear, clean them up deliberately before retrying.
6. On partitioned tables, create the same definition on child partitions first and only then add the parent metadata index; skip `ATTACH PARTITION`.
7. Review redundant, unused, and bloated indexes, then run `VACUUM (ANALYZE)` or `ANALYZE` after drops or major churn.

## Output Contract

- Describe the target query pattern and the chosen index shape.
- State whether the final design is full, partial, composite, or partitioned.
- Report the validation evidence used: `EXPLAIN`, `indisvalid`, progress view, unused-index stats, or bloat checks.
- If partitioned tables are involved, explicitly say child indexes were handled before the parent definition.
- Mention any operational risk: over-indexing, invalid concurrent build, deadlock risk during parallel reindex, or stats refresh required.

## References

- `api/src/backend/api/db_utils.py`
- `api/src/backend/api/partitions.py`
- `skills/django-migration-psql/SKILL.md`
- `api/src/backend/**/migrations/`
