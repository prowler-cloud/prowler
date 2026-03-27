---
name: django-migration-psql
description: >
  Reviews Django migration files for PostgreSQL best practices specific to Prowler.
  Trigger: When creating migrations, running makemigrations/pgmakemigrations, reviewing migration PRs,
  adding indexes or constraints to database tables, modifying existing migration files, or writing
  data backfill migrations. Always use this skill when you see AddIndex, CreateModel, AddConstraint,
  RunPython, bulk_create, bulk_update, or backfill operations in migration files.
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

## When to use

- Creating a new Django migration
- Running `makemigrations` or `pgmakemigrations`
- Reviewing a PR that adds or modifies migrations
- Adding indexes, constraints, or models to the database

## Why this matters

A bad migration can lock a production table for minutes, block all reads/writes, or silently skip index creation on partitioned tables.

## Auto-generated migrations need splitting

`makemigrations` and `pgmakemigrations` bundle everything into one file: `CreateModel`, `AddIndex`, `AddConstraint`, sometimes across multiple tables. This is the default Django behavior and it violates every rule below.

After generating a migration, ALWAYS review it and split it:

1. Read the generated file and identify every operation
2. Group operations by concern:
   - `CreateModel` + `AddConstraint` for each new table → one migration per table
   - `AddIndex` per table → one migration per table
   - `AddIndex` on partitioned tables → two migrations (partition + parent)
   - `AlterField`, `AddField`, `RemoveField` for each table → one migration per table
3. Rewrite the generated file into separate migration files with correct dependencies
4. Delete the original auto-generated migration

When adding fields or indexes to an existing model, `makemigrations` may also bundle `AddIndex` for unrelated tables that had pending model changes. Always check for stowaways from other tables.

## Rule 1: separate indexes from model creation

`CreateModel` + `AddConstraint` = same migration (structural).
`AddIndex` = separate migration file (performance).

Django runs each migration inside a transaction (unless `atomic = False`). If an index operation fails, it rolls back everything, including the model creation. Splitting means a failed index doesn't prevent the table from existing. It also lets you `--fake` index migrations independently (see Rule 4).

### Bad

```python
# 0081_finding_group_daily_summary.py — DON'T DO THIS
class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(name="FindingGroupDailySummary", ...),
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),  # separate this
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),  # separate this
        migrations.AddConstraint(model_name="findinggroupdailysummary", ...),  # this is fine here
    ]
```

### Good

```python
# 0081_create_finding_group_daily_summary.py
class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(name="FindingGroupDailySummary", ...),
        # Constraints belong with the model — they define its integrity rules
        migrations.AddConstraint(model_name="findinggroupdailysummary", ...),  # unique
        migrations.AddConstraint(model_name="findinggroupdailysummary", ...),  # RLS
    ]

# 0082_finding_group_daily_summary_indexes.py
class Migration(migrations.Migration):
    dependencies = [("api", "0081_create_finding_group_daily_summary")]
    operations = [
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),
    ]
```

Flag any migration with both `CreateModel` and `AddIndex` in `operations`.

## Rule 2: one table's indexes per migration

Each table's indexes must live in their own migration file. Never mix `AddIndex` for different `model_name` values in one migration.

If the index on table B fails, the rollback also drops the index on table A. The migration name gives no hint that it touches unrelated tables. You lose the ability to `--fake` one table's indexes without affecting the other.

### Bad

```python
# 0081_finding_group_daily_summary.py — DON'T DO THIS
class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(name="FindingGroupDailySummary", ...),
        migrations.AddIndex(model_name="findinggroupdailysummary", ...),  # table A
        migrations.AddIndex(model_name="resource", ...),                  # table B!
        migrations.AddIndex(model_name="resource", ...),                  # table B!
        migrations.AddIndex(model_name="finding", ...),                   # table C!
    ]
```

### Good

```python
# 0081_create_finding_group_daily_summary.py  — model + constraints
# 0082_finding_group_daily_summary_indexes.py — only FindingGroupDailySummary indexes
# 0083_resource_trigram_indexes.py            — only Resource indexes
# 0084_finding_check_index_partitions.py      — only Finding partition indexes (step 1)
# 0085_finding_check_index_parent.py          — only Finding parent index (step 2)
```

Name each migration file after the table it affects. A reviewer should know which table a migration touches without opening the file.

Flag any migration where `AddIndex` operations reference more than one `model_name`.

## Rule 3: partitioned table indexes require the two-step pattern

Tables `findings` and `resource_finding_mappings` are range-partitioned. Plain `AddIndex` only creates the index definition on the parent table. Postgres does NOT propagate it to existing partitions. New partitions inherit it, but all current data stays unindexed.

Use the helpers in `api.db_utils`.

### Step 1: create indexes on actual partitions

```python
# 0084_finding_check_index_partitions.py
from functools import partial
from django.db import migrations
from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False  # REQUIRED — CREATE INDEX CONCURRENTLY can't run inside a transaction

    dependencies = [("api", "0083_resource_trigram_indexes")]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_check_ins_idx",
                columns="tenant_id, check_id, inserted_at",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_check_ins_idx",
            ),
        )
    ]
```

Key details:
- `atomic = False` is mandatory. `CREATE INDEX CONCURRENTLY` cannot run inside a transaction.
- Always provide `reverse_code` using `drop_index_on_partitions` so rollbacks work.
- The default is `all_partitions=True`, which creates indexes on every partition CONCURRENTLY (no locks). This is the safe default.
- Do NOT use `all_partitions=False` unless you understand the consequence: Step 2's `AddIndex` on the parent will create indexes on the skipped partitions **with locks** (not CONCURRENTLY), because PostgreSQL fills in missing partition indexes inline during parent index creation.

### Step 2: register the index with Django

```python
# 0085_finding_check_index_parent.py
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0084_finding_check_index_partitions")]

    operations = [
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "check_id", "inserted_at"],
                name="find_tenant_check_ins_idx",
            ),
        ),
    ]
```

This second migration tells Django "this index exists" so it doesn't try to recreate it. New partitions created after this point inherit the index definition from the parent.

### Existing examples in the codebase

| Partition migration | Parent migration |
|---|---|
| `0020_findings_new_performance_indexes_partitions.py` | `0021_findings_new_performance_indexes_parent.py` |
| `0024_findings_uid_index_partitions.py` | `0025_findings_uid_index_parent.py` |
| `0028_findings_check_index_partitions.py` | `0029_findings_check_index_parent.py` |
| `0036_rfm_tenant_finding_index_partitions.py` | `0037_rfm_tenant_finding_index_parent.py` |

Flag any plain `AddIndex` on `finding` or `resourcefindingmapping` without a preceding partition migration.

## Rule 4: large table indexes — fake the migration, apply manually

For huge tables (findings has millions of rows), even `CREATE INDEX CONCURRENTLY` can take minutes and consume significant I/O. In production, you may want to decouple the migration from the actual index creation.

### Procedure

1. Write the migration normally following the two-step pattern above.

2. Fake the migration so Django marks it as applied without executing it:

```bash
python manage.py migrate api 0084_finding_check_index_partitions --fake
python manage.py migrate api 0085_finding_check_index_parent --fake
```

3. Create the index manually during a low-traffic window via `psql` or `python manage.py dbshell --database admin`:

```sql
-- For each partition you care about:
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_2026_jan_find_tenant_check_ins_idx
    ON findings_2026_jan USING BTREE (tenant_id, check_id, inserted_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_2026_feb_find_tenant_check_ins_idx
    ON findings_2026_feb USING BTREE (tenant_id, check_id, inserted_at);

-- Then register on the parent (this is fast, no data scan):
CREATE INDEX IF NOT EXISTS find_tenant_check_ins_idx
    ON findings USING BTREE (tenant_id, check_id, inserted_at);
```

4. Verify the index exists on the partitions you need:

```sql
SELECT indexrelid::regclass, indrelid::regclass
FROM pg_index
WHERE indexrelid::regclass::text LIKE '%find_tenant_check_ins%';
```

### When to use this approach

- The table will grow exponentially, e.g.: findings.
- You want to control exactly when the I/O hit happens (e.g., during a maintenance window).

This is optional. For smaller tables or non-production environments, letting the migration run normally is fine.

## Rule 5: data backfills — never inline, always batched

Data backfills (updating existing rows, populating new columns, generating summary data) are the most dangerous migrations. A naive `Model.objects.all().update(...)` on a multi-million row table will hold a transaction lock for minutes, blow out WAL, and potentially OOM the worker.

### Never backfill inline in the migration

The migration should only dispatch the work. The actual backfill runs asynchronously via Celery tasks, outside the migration transaction.

```python
# 0090_backfill_finding_group_summaries.py
from django.db import migrations

def trigger_backfill(apps, schema_editor):
    from tasks.jobs.backfill import backfill_finding_group_summaries_task
    Tenant = apps.get_model("api", "Tenant")
    from api.db_router import MainRouter

    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    for tenant_id in tenant_ids:
        backfill_finding_group_summaries_task.delay(tenant_id=str(tenant_id))

class Migration(migrations.Migration):
    dependencies = [("api", "0089_previous_migration")]
    operations = [
        migrations.RunPython(trigger_backfill, migrations.RunPython.noop),
    ]
```

The migration finishes in seconds. The backfill runs in the background per-tenant.

### Exception: trivial updates

Single-statement bulk updates on small result sets are OK inline:

```python
# Fine — single UPDATE, small result set, no iteration
def backfill_graph_data_ready(apps, schema_editor):
    AttackPathsScan = apps.get_model("api", "AttackPathsScan")
    AttackPathsScan.objects.using(MainRouter.admin_db).filter(
        state="completed", graph_data_ready=False,
    ).update(graph_data_ready=True)
```

Use inline only when you're confident the affected row count is small (< ~10K rows).

### Batch processing in the Celery task

The actual backfill task must process data in batches. Use the helpers in `api.db_utils`:

```python
from api.db_utils import create_objects_in_batches, update_objects_in_batches, batch_delete

# Creating objects in batches (500 per transaction)
create_objects_in_batches(tenant_id, ScanCategorySummary, summaries, batch_size=500)

# Updating objects in batches
update_objects_in_batches(tenant_id, Finding, findings, fields=["status"], batch_size=500)

# Deleting in batches
batch_delete(tenant_id, queryset, batch_size=settings.DJANGO_DELETION_BATCH_SIZE)
```

Each batch runs in its own `rls_transaction()` so:
- A failure in batch N doesn't roll back batches 1 through N-1
- Lock duration is bounded to the batch size
- Memory stays constant regardless of total row count

### Rules for backfill tasks

1. **One RLS transaction per batch.** Never wrap the entire backfill in a single transaction. Each batch gets its own `rls_transaction(tenant_id)`.

2. **Use `bulk_create` / `bulk_update` with explicit `batch_size`.** Never `.save()` in a loop. The default batch_size is 500.

3. **Use `.iterator()` for reads.** When reading source data, use `queryset.iterator()` to avoid loading the entire result set into memory.

4. **Use `.only()` / `.values_list()` for reads.** Fetch only the columns you need, not full model instances.

5. **Catch and skip per-item failures.** Don't let one bad row kill the entire backfill. Log the error, count it, continue.

```python
scans_processed = 0
scans_skipped = 0

for scan_id in scan_ids:
    try:
        result = process_scan(tenant_id, scan_id)
        scans_processed += 1
    except Exception:
        logger.warning("Failed to process scan %s", scan_id)
        scans_skipped += 1

logger.info("Backfill done: %d processed, %d skipped", scans_processed, scans_skipped)
```

6. **Log totals at start and end, not per-batch.** Per-batch logging floods the logs. Log the total count at the start, and the processed/skipped counts at the end.

7. **Use `ignore_conflicts=True` for idempotent creates.** Makes the backfill safe to re-run if interrupted.

```python
Model.objects.bulk_create(objects, batch_size=500, ignore_conflicts=True)
```

8. **Iterate per-tenant.** Dispatch one Celery task per tenant. This gives you natural parallelism, bounded memory per task, and the ability to retry a single tenant without re-running everything.

### Existing examples

| Migration | Task |
|---|---|
| `0062_backfill_daily_severity_summaries.py` | `backfill_daily_severity_summaries_task` |
| `0080_backfill_attack_paths_graph_data_ready.py` | Inline (trivial update) |
| `0082_backfill_finding_group_summaries.py` | `backfill_finding_group_summaries_task` |

Task implementations: `tasks/jobs/backfill.py`
Batch utilities: `api/db_utils.py` (`batch_delete`, `create_objects_in_batches`, `update_objects_in_batches`)

## Decision tree

```
Auto-generated migration?
├── Yes → Split it following the rules below
└── No → Review it against the rules below

New model?
├── Yes → CreateModel + AddConstraint in one migration
│         AddIndex in separate migration(s), one per table
└── No, just indexes?
│   ├── Regular table → AddIndex in its own migration
│   └── Partitioned table (findings, resource_finding_mappings)?
│       ├── Step 1: RunPython + create_index_on_partitions (atomic=False)
│       └── Step 2: AddIndex on parent (separate migration)
│           └── Large table? → Consider --fake + manual apply
└── Data backfill?
    ├── Trivial update (< ~10K rows)? → Inline RunPython is OK
    └── Large backfill? → Migration dispatches Celery task(s)
        ├── One task per tenant
        ├── Batch processing (bulk_create/bulk_update, batch_size=500)
        ├── One rls_transaction per batch
        └── Catch + skip per-item failures, log totals
```

## Quick reference

| Scenario | Approach |
|---|---|
| Auto-generated migration | Split by concern and table before committing |
| New model + constraints/RLS | Same migration (constraints are structural) |
| Indexes on a regular table | Separate migration, one table per file |
| Indexes on a partitioned table | Two migrations: partitions first (`RunPython` + `atomic=False`), then parent (`AddIndex`) |
| Index on a huge partitioned table | Same two migrations, but fake + apply manually in production |
| Trivial data backfill (< ~10K rows) | Inline `RunPython` with single `.update()` call |
| Large data backfill | Migration dispatches Celery task per tenant, task batches with `rls_transaction` |

## Review output format

1. List each violation with rule number and one-line explanation
2. Show corrected migration file(s)
3. For partitioned tables, show both partition and parent migrations

If migration passes all checks, say so.

## Context7 lookups

**Prerequisite:** Install Context7 MCP server for up-to-date documentation lookup.

When implementing or debugging migration patterns, query these libraries via `mcp_context7_query-docs`:

| Library | Context7 ID | Use for |
|---------|-------------|---------|
| Django 5.1 | `/websites/djangoproject_en_5_1` | Migration operations, indexes, constraints, `SchemaEditor` |
| PostgreSQL | `/websites/postgresql_org_docs_current` | `CREATE INDEX CONCURRENTLY`, partitioned tables, `pg_inherits` |
| django-postgres-extra | `/SectorLabs/django-postgres-extra` | Partitioned models, `PostgresPartitionedModel`, partition management |

**Example queries:**
```
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_1", query="migration operations AddIndex RunPython atomic")
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_1", query="database indexes Meta class concurrently")
mcp_context7_query-docs(libraryId="/websites/postgresql_org_docs_current", query="CREATE INDEX CONCURRENTLY partitioned table")
mcp_context7_query-docs(libraryId="/SectorLabs/django-postgres-extra", query="partitioned model range partition index")
```

> **Note:** Use `mcp_context7_resolve-library-id` first if you need to find the correct library ID.

## Commands

```bash
# Generate migrations (ALWAYS review output before committing)
python manage.py makemigrations
python manage.py pgmakemigrations

# Apply migrations
python manage.py migrate

# Fake a migration (mark as applied without running)
python manage.py migrate api <migration_name> --fake

# Manage partitions
python manage.py pgpartition --using admin
```

## Resources

- **Partition helpers**: `api/src/backend/api/db_utils.py` (`create_index_on_partitions`, `drop_index_on_partitions`)
- **Partition config**: `api/src/backend/api/partitions.py`
- **RLS constraints**: `api/src/backend/api/rls.py`
- **Existing examples**: `0028` + `0029`, `0024` + `0025`, `0036` + `0037`
