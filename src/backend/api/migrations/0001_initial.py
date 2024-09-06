import uuid
from functools import partial

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models
from uuid6 import uuid7

import api.rls
from api.db_utils import (
    PostgresEnumMigration,
    ProviderEnum,
    ProviderEnumField,
    ScanTriggerEnum,
    StateEnumField,
    StateEnum,
    ScanTriggerEnumField,
    register_enum,
)
from api.models import Provider, Scan, StateChoices

DB_NAME = settings.DATABASES["default"]["NAME"]
DB_USER_NAME = (
    settings.DATABASES["prowler_user"]["USER"] if not settings.TESTING else "test"
)
DB_USER_PASSWORD = (
    settings.DATABASES["prowler_user"]["PASSWORD"] if not settings.TESTING else "test"
)

ProviderEnumMigration = PostgresEnumMigration(
    enum_name="provider",
    enum_values=tuple(provider[0] for provider in Provider.ProviderChoices.choices),
)

ScanTriggerEnumMigration = PostgresEnumMigration(
    enum_name="scan_trigger",
    enum_values=tuple(scan_trigger[0] for scan_trigger in Scan.TriggerChoices.choices),
)

StateEnumMigration = PostgresEnumMigration(
    enum_name="state",
    enum_values=tuple(state[0] for state in StateChoices.choices),
)


class Migration(migrations.Migration):
    initial = True
    # Required for our kind of `RunPython` operations
    atomic = False

    dependencies = []

    operations = [
        migrations.RunSQL(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT
                    FROM   pg_catalog.pg_roles
                    WHERE  rolname = '{DB_USER_NAME}') THEN
                    CREATE ROLE {DB_USER_NAME} LOGIN PASSWORD '{DB_USER_PASSWORD}';
                END IF;
            END
            $$;
            """
        ),
        migrations.RunSQL(
            # `runserver` command for dev tools requires read access to migrations
            f"""
            GRANT CONNECT ON DATABASE "{DB_NAME}" TO {DB_USER_NAME};
            GRANT SELECT ON django_migrations TO {DB_USER_NAME};
            """
        ),
        # Create and register State type
        migrations.RunPython(
            StateEnumMigration.create_enum_type,
            reverse_code=StateEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=StateEnum)),
        migrations.CreateModel(
            name="Tenant",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=100)),
            ],
            options={
                "db_table": "tenants",
            },
        ),
        migrations.RunSQL(
            # Needed for now since we don't have users yet
            f"""
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenants TO {DB_USER_NAME};
            """
        ),
        # Create and register ProviderEnum type
        migrations.RunPython(
            ProviderEnumMigration.create_enum_type,
            reverse_code=ProviderEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=ProviderEnum)),
        migrations.CreateModel(
            name="Provider",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "provider",
                    ProviderEnumField(
                        choices=[
                            ("aws", "AWS"),
                            ("azure", "Azure"),
                            ("gcp", "GCP"),
                            ("kubernetes", "Kubernetes"),
                        ],
                        default="aws",
                    ),
                ),
                (
                    "provider_id",
                    models.CharField(
                        max_length=63,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                (
                    "alias",
                    models.CharField(
                        blank=True,
                        null=True,
                        max_length=100,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                ("connected", models.BooleanField(blank=True, null=True)),
                (
                    "connection_last_checked_at",
                    models.DateTimeField(blank=True, null=True),
                ),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("scanner_args", models.JSONField(blank=True, default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "abstract": False,
                "db_table": "providers",
            },
        ),
        migrations.AddConstraint(
            model_name="provider",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_provider",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="provider",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider", "provider_id"),
                name="unique_provider_ids",
            ),
        ),
        # Create and register ScanTriggerEnum type
        migrations.RunPython(
            ScanTriggerEnumMigration.create_enum_type,
            reverse_code=ScanTriggerEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=ScanTriggerEnum)),
        migrations.CreateModel(
            name="Scan",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        blank=True,
                        max_length=100,
                        null=True,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                (
                    "trigger",
                    ScanTriggerEnumField(
                        choices=[("scheduled", "Scheduled"), ("manual", "Manual")]
                    ),
                ),
                (
                    "state",
                    StateEnumField(
                        choices=[
                            ("available", "Available"),
                            ("scheduled", "Scheduled"),
                            ("executing", "Executing"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="available",
                    ),
                ),
                ("unique_resource_count", models.IntegerField(default=0)),
                ("progress", models.IntegerField(default=0)),
                ("scanner_args", models.JSONField(default=dict)),
                ("duration", models.IntegerField(blank=True, null=True)),
                (
                    "scheduled_at",
                    models.DateTimeField(null=True, blank=True),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("completed_at", models.DateTimeField(null=True, blank=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scans",
                        related_query_name="scan",
                        to="api.provider",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "scans",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="scan",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scan",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="scan",
            index=models.Index(
                fields=["provider", "state", "trigger", "scheduled_at"],
                name="scans_prov_state_trig_sche_idx",
            ),
        ),
    ]
