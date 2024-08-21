import uuid
from functools import partial

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import api.rls
from api.db_utils import (
    PostgresEnumMigration,
    register_enum,
    ProviderEnumField,
    ProviderEnum,
)
from api.models import Provider

DB_NAME = settings.DATABASES["default"]["NAME"]
DB_USER_NAME = settings.DATABASES["default"]["USER"]
DB_USER_PASSWORD = settings.DATABASES["default"]["PASSWORD"]

ProviderEnumMigration = PostgresEnumMigration(
    enum_name="provider",
    enum_values=tuple(provider[0] for provider in Provider.ProviderChoices.choices),
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
    ]
