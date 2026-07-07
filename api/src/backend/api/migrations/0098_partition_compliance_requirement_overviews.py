"""Convert ``compliance_requirements_overviews`` into a RANGE-partitioned table.

The compliance-overview ingest rewrites every scan's rows (delete-then-reinsert),
which — together with old scans ageing out — generates heavy autovacuum churn on a
plain table. Partitioning RANGE by the UUIDv7 ``id`` (same strategy as ``findings``)
lets old data be reclaimed with ``DROP PARTITION`` instead of ``DELETE`` + CASCADE.

Existing data is preserved WITHOUT a copy: the current table is renamed and
re-attached as the ``default`` partition of a new partitioned parent (ATTACH is a
metadata operation, so there is no row rewrite). Existing rows keep their uuid4
ids and live in ``default``; new rows carry uuid7 ids and route to the monthly
partitions created by ``pgpartition``.

NOTE for production: rename + ATTACH take a brief ACCESS EXCLUSIVE lock and adding
the parent FKs validates the default partition. Run during a low-traffic window (or
``--fake`` + apply manually) on large tables, and rehearse against a prod snapshot —
this is delicate DDL with no in-repo precedent. See skills/django-migration-psql.
"""

import api.rls
import psqlextra.manager.manager
import uuid6
from api.rls import RowLevelSecurityConstraint
from django.db import migrations, models

TABLE = "compliance_requirements_overviews"
DEFAULT = f"{TABLE}_default"
INDEX = "cro_scan_comp_reg_idx"
UNIQUE = "unique_tenant_compliance_requirement_overview"
PARENT_RLS = "rls_on_compliancerequirementoverview"
DEFAULT_RLS = "rls_on_compliancerequirementoverview_default"


def _partition_table(apps, schema_editor):
    model = apps.get_model("api", "ComplianceRequirementOverview")
    cursor = schema_editor.connection.cursor

    # 1. Drop the old RLS (created in 0027 with SELECT/INSERT/UPDATE/DELETE) via the
    #    constraint object so the DB_USER-scoped policy/grant names resolve correctly.
    schema_editor.remove_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id",
            name=PARENT_RLS,
            statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
        ),
    )

    with cursor() as cur:
        # 2. Drop the old business unique (5 cols) — after partitioning, dedup is
        #    handled by the delete-then-reinsert ingest (the model keeps no unique).
        cur.execute(f"ALTER TABLE {TABLE} DROP CONSTRAINT {UNIQUE};")

        # 3. Rename the existing table and every object whose name the new parent
        #    will reuse, moving them under the ``_default`` name. The default keeps
        #    its own FKs, so the parent FKs added below skip re-validation on ATTACH.
        cur.execute(f"ALTER TABLE {TABLE} RENAME TO {DEFAULT};")
        cur.execute(
            f"ALTER TABLE {DEFAULT} RENAME CONSTRAINT {TABLE}_pkey TO {DEFAULT}_pkey;"
        )
        cur.execute(f"ALTER INDEX {INDEX} RENAME TO {INDEX}_default;")

        # 4. Create the partitioned parent and re-establish its structure.
        cur.execute(
            f"CREATE TABLE {TABLE} (LIKE {DEFAULT} INCLUDING DEFAULTS) "
            "PARTITION BY RANGE (id);"
        )
        cur.execute(
            f"ALTER TABLE {TABLE} ADD CONSTRAINT {TABLE}_pkey PRIMARY KEY (id);"
        )
        # Parent index ON ONLY (no data), then attach the pre-built default index so
        # the existing rows are NOT re-indexed.
        cur.execute(
            f"CREATE INDEX {INDEX} ON ONLY {TABLE} "
            "(tenant_id, scan_id, compliance_id, region);"
        )

        # 5. Add FKs on the STILL-EMPTY parent (instant, no scan) so new partitions
        #    inherit referential integrity. Postgres cannot add NOT VALID FKs to a
        #    partitioned table, but because the default partition already carries an
        #    equivalent valid FK, the ATTACH below skips FK re-validation. Cascade on
        #    scan/tenant deletion is still handled at the ORM level.
        cur.execute(
            f"ALTER TABLE {TABLE} ADD CONSTRAINT {TABLE}_scan_id_fk "
            "FOREIGN KEY (scan_id) REFERENCES scans (id) DEFERRABLE INITIALLY DEFERRED;"
        )
        cur.execute(
            f"ALTER TABLE {TABLE} ADD CONSTRAINT {TABLE}_tenant_id_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants (id) DEFERRABLE INITIALLY DEFERRED;"
        )

        # 6. Attach the existing table (with all its rows) as the DEFAULT partition
        #    and attach its pre-built index to the parent's partitioned index.
        cur.execute(f"ALTER TABLE {TABLE} ATTACH PARTITION {DEFAULT} DEFAULT;")
        cur.execute(f"ALTER INDEX {INDEX} ATTACH PARTITION {INDEX}_default;")

    # 7. Re-establish RLS on the parent and the default partition (DB_USER-aware).
    schema_editor.add_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id", name=PARENT_RLS, statements=["SELECT", "INSERT", "DELETE"]
        ),
    )
    schema_editor.add_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id",
            name=DEFAULT_RLS,
            partition_name="default",
            statements=["SELECT", "INSERT", "DELETE"],
        ),
    )


def _unpartition_table(apps, schema_editor):
    """Best-effort reverse: detach the default partition and restore a plain table."""
    model = apps.get_model("api", "ComplianceRequirementOverview")
    cursor = schema_editor.connection.cursor

    schema_editor.remove_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id",
            name=DEFAULT_RLS,
            partition_name="default",
            statements=["SELECT", "INSERT", "DELETE"],
        ),
    )
    schema_editor.remove_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id", name=PARENT_RLS, statements=["SELECT", "INSERT", "DELETE"]
        ),
    )

    with cursor() as cur:
        # Detach the default partition (keeps its own pkey/index/FKs) and drop the
        # partitioned parent, then rename the default back to the original table.
        cur.execute(f"ALTER INDEX {INDEX} DETACH PARTITION {INDEX}_default;")
        cur.execute(f"ALTER TABLE {TABLE} DETACH PARTITION {DEFAULT};")
        cur.execute(f"DROP TABLE {TABLE};")
        cur.execute(f"ALTER TABLE {DEFAULT} RENAME TO {TABLE};")
        cur.execute(
            f"ALTER TABLE {TABLE} RENAME CONSTRAINT {DEFAULT}_pkey TO {TABLE}_pkey;"
        )
        cur.execute(f"ALTER INDEX {INDEX}_default RENAME TO {INDEX};")
        # Restore the original 5-column business unique (the FKs survived on the
        # detached table, so they are not re-created here).
        cur.execute(
            f"ALTER TABLE {TABLE} ADD CONSTRAINT {UNIQUE} "
            "UNIQUE (tenant_id, scan_id, compliance_id, requirement_id, region);"
        )

    schema_editor.add_constraint(
        model,
        RowLevelSecurityConstraint(
            "tenant_id",
            name=PARENT_RLS,
            statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
        ),
    )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0097_attack_paths_scan_db_defaults"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # State: mirror what pgmakemigrations detected (minus unrelated stowaways)
            # so the ORM state matches the partitioned model definition.
            state_operations=[
                migrations.AlterModelOptions(
                    name="compliancerequirementoverview",
                    options={"base_manager_name": "objects"},
                ),
                migrations.AlterModelManagers(
                    name="compliancerequirementoverview",
                    managers=[
                        ("objects", psqlextra.manager.manager.PostgresManager()),
                    ],
                ),
                migrations.RemoveConstraint(
                    model_name="compliancerequirementoverview",
                    name=UNIQUE,
                ),
                migrations.AlterField(
                    model_name="compliancerequirementoverview",
                    name="id",
                    field=models.UUIDField(
                        default=uuid6.uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                migrations.AddConstraint(
                    model_name="compliancerequirementoverview",
                    constraint=api.rls.RowLevelSecurityConstraint(
                        "tenant_id", name=DEFAULT_RLS
                    ),
                ),
            ],
            database_operations=[
                migrations.RunPython(_partition_table, _unpartition_table),
            ],
        ),
    ]
