---
name: django-migration-psql
description: >
  Reviews Django migration files for PostgreSQL best practices specific to Prowler.
  Trigger: When creating migrations, running makemigrations/pgmakemigrations, reviewing migration PRs,
  adding indexes or constraints to database tables, or modifying existing migration files.
  Always use this skill when you see AddIndex, CreateModel, or AddConstraint operations in migration files.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [api]
  auto_invoke:
    - "Creating or reviewing Django migrations"
    - "Adding indexes or constraints to database tables"
    - "Running makemigrations or pgmakemigrations"
allowed-tools: Read, Grep, Glob
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
- Use `all_partitions=False` (default) to skip old partitions where the index isn't needed.
- Use `all_partitions=True` only when migrating existing critical indexes that must cover historical data.

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

- The table has more than ~10M rows.
- The deployment pipeline has a migration timeout that the index creation would exceed.
- You want to control exactly when the I/O hit happens (e.g., during a maintenance window).

This is optional. For smaller tables or non-production environments, letting the migration run normally is fine.

## Decision tree

```
Auto-generated migration?
├── Yes → Split it following the rules below
└── No → Review it against the rules below

New model?
├── Yes → CreateModel + AddConstraint in one migration
│         AddIndex in separate migration(s), one per table
└── No, just indexes?
    ├── Regular table → AddIndex in its own migration
    └── Partitioned table (findings, resource_finding_mappings)?
        ├── Step 1: RunPython + create_index_on_partitions (atomic=False)
        └── Step 2: AddIndex on parent (separate migration)
            └── Large table? → Consider --fake + manual apply
```

## Quick reference

| Scenario | Approach |
|---|---|
| Auto-generated migration | Split by concern and table before committing |
| New model + constraints/RLS | Same migration (constraints are structural) |
| Indexes on a regular table | Separate migration, one table per file |
| Indexes on a partitioned table | Two migrations: partitions first (`RunPython` + `atomic=False`), then parent (`AddIndex`) |
| Index on a huge partitioned table | Same two migrations, but fake + apply manually in production |

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
| Django 5.2 | `/websites/djangoproject_en_5_2` | Migration operations, indexes, constraints, `SchemaEditor` |
| PostgreSQL | `/websites/postgresql_org_docs_current` | `CREATE INDEX CONCURRENTLY`, partitioned tables, `pg_inherits` |
| django-postgres-extra | `/SectorLabs/django-postgres-extra` | Partitioned models, `PostgresPartitionedModel`, partition management |

**Example queries:**
```
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_2", query="migration operations AddIndex RunPython atomic")
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_2", query="database indexes Meta class concurrently")
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
