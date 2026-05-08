---
name: django-migration-psql
description: "Trigger: When creating, reviewing, or splitting Django/PostgreSQL migrations with AddIndex, CreateModel, AddConstraint, RunPython, or backfill logic. Enforces Prowler-safe migration structure for indexes, partitioned tables, and large data moves."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [api, root]
  auto_invoke:
    - "Creating or reviewing Django migrations"
    - "Adding indexes or constraints to database tables"
    - "Running makemigrations or pgmakemigrations"
    - "Writing data backfill or data migration"
allowed-tools: Read, Grep, Glob, Edit, Write, Bash
---

## Activation Contract

Use this skill when a migration changes schema, indexes, partitioned tables, or existing data in the Prowler API database.

## Hard Rules

- Never trust auto-generated migrations as-is; review and split them by concern and table.
- Keep `CreateModel` plus integrity constraints together, but move every `AddIndex` into separate migration files.
- Never mix indexes for multiple tables in one migration.
- `finding` and `resourcefindingmapping` partitioned indexes require the two-step pattern: partition creation first, parent `AddIndex` second.
- Partition index creation with `RunPython(create_index_on_partitions, ...)` MUST use `atomic = False` and include `reverse_code`.
- Large backfills must dispatch Celery work; do not iterate millions of rows inside the migration transaction.
- Inline backfills are allowed only for trivial, single-statement updates on small result sets.
- Backfill tasks must batch writes, use one `rls_transaction()` per batch, and avoid `.save()` loops.

## Decision Gates

| Question | Action |
|---|---|
| Did `makemigrations` bundle unrelated operations together? | Rewrite into focused files and delete the generated catch-all migration. |
| New table plus indexes? | Put `CreateModel` and constraints together, then create separate index migration(s). |
| Multiple `model_name` values in one `AddIndex` migration? | Split into one migration per table. |
| Indexing `finding` or `resourcefindingmapping`? | Use partition helper migration first, then parent `AddIndex` migration. |
| Very large partitioned table in production? | Consider fake-applying the migration and creating indexes manually during a maintenance window. |
| Data migration larger than trivial update scope? | Dispatch one Celery task per tenant and batch inside the task. |

## Execution Steps

1. Read the generated or reviewed migration and list every operation by table and by concern.
2. Split structural work (`CreateModel`, `AddConstraint`, field changes) from performance work (`AddIndex`).
3. For regular-table indexes, create one migration per table with only that table's `AddIndex` operations.
4. For partitioned tables, write migration A with `RunPython(create_index_on_partitions, reverse_code=drop_index_on_partitions)` and `atomic = False`, then migration B with the parent `AddIndex` so Django registers the index definition.
5. If the table is huge, document whether the safe path is normal execution or `--fake` plus manual concurrent index creation.
6. For data backfills, keep the migration as a dispatcher only unless the change is a tiny single `UPDATE`; move real work into Celery tasks that batch reads/writes, use `.iterator()`, fetch only needed columns, and tolerate per-item failures.
7. Re-verify dependencies, migration names, and rollback behavior before finishing.

## Output Contract

- State whether the migration was accepted as-is or rewritten.
- List each violation found with the governing rule: mixed concerns, mixed tables, missing partition step, unsafe backfill, or transaction misuse.
- Show the final migration shape expected: structural file, per-table index file(s), and partition/parent pair when applicable.
- If a backfill is involved, say whether it is inline-trivial or Celery-dispatched and why.
- Mention the exact validation command or migration command used.

## References

- `api/src/backend/api/db_utils.py`
- `api/src/backend/api/partitions.py`
- `api/src/backend/api/rls.py`
- `api/src/backend/tasks/jobs/backfill.py`
- `api/src/backend/**/migrations/`
- Existing partition examples: `0024` + `0025`, `0028` + `0029`, `0036` + `0037`
