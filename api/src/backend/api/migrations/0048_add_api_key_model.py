# Generated manually for API Key model with multi-tenancy and RBAC support
# This migration creates API keys with secure prefix-based lookup, tenant management, and role-based permissions

import uuid

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models

from api.rls import RowLevelSecurityConstraint


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0047_remove_integration_unique_configuration_per_tenant.py"),
    ]

    operations = [
        migrations.CreateModel(
            name="APIKey",
            fields=[
                (
                    "id",
                    models.CharField(
                        editable=False,
                        max_length=150,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        unique=True,
                        help_text="UUID for external API references",
                    ),
                ),
                (
                    "prefix",
                    models.CharField(editable=False, max_length=15, unique=True),
                ),
                ("hashed_key", models.CharField(editable=False, max_length=150)),
                ("created", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "name",
                    models.CharField(
                        default=None,
                        help_text="A free-form name for the API key. Need not be unique. 50 characters max.",
                        max_length=50,
                    ),
                ),
                (
                    "revoked",
                    models.BooleanField(
                        blank=True,
                        default=False,
                        help_text="If the API key is revoked, clients cannot use it anymore. (This cannot be undone.)",
                    ),
                ),
                (
                    "expiry_date",
                    models.DateTimeField(
                        blank=True,
                        help_text="Once API key expires, clients cannot use it anymore.",
                        null=True,
                        verbose_name="Expires",
                    ),
                ),
                (
                    "last_used_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="Last time this API key was used",
                        null=True,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
                (
                    "role",
                    models.ForeignKey(
                        help_text="Role that defines the permissions for this API key",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="api_keys",
                        to="api.role",
                    ),
                ),
            ],
            options={
                "verbose_name": "API key",
                "verbose_name_plural": "API keys",
                "db_table": "api_keys",
                "ordering": ("-created",),
                "abstract": False,
            },
        ),
        # Add indexes
        migrations.AddIndex(
            model_name="apikey",
            index=models.Index(
                fields=["tenant_id", "prefix"], name="api_keys_tenant_prefix_idx"
            ),
        ),
        # Add RLS constraint
        migrations.AddConstraint(
            model_name="apikey",
            constraint=RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_apikey",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
