# Generated manually for API Key model with multi-tenancy
# This migration creates API keys with secure prefix-based lookup and tenant management

import django.core.validators
from django.db import migrations, models
import uuid

from api.rls import RowLevelSecurityConstraint


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0043_github_provider"),
    ]

    operations = [
        migrations.CreateModel(
            name="APIKey",
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
                (
                    "name",
                    models.CharField(
                        max_length=255,
                        validators=[django.core.validators.MinLengthValidator(3)],
                        help_text="Human-readable name to identify the API key",
                    ),
                ),
                (
                    "key_hash",
                    models.CharField(
                        max_length=255,
                        unique=True,
                        help_text="Django password hash of the API key",
                    ),
                ),
                (
                    "prefix",
                    models.CharField(
                        max_length=10,
                        help_text="Prefix of the API key for identification",
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="Expiration time. Null means no expiration.",
                    ),
                ),
                (
                    "last_used_at",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="Last time this API key was used",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "revoked_at",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="Time when the key was revoked. Null means active.",
                    ),
                ),
                (
                    "tenant_id",
                    models.UUIDField(help_text="Tenant ID for multi-tenancy support"),
                ),
            ],
            options={
                "db_table": "api_keys",
            },
        ),
        migrations.AddIndex(
            model_name="apikey",
            index=models.Index(
                fields=["tenant_id", "prefix"], name="api_keys_tenant_prefix_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="apikey",
            index=models.Index(
                fields=["tenant_id", "revoked_at"], name="api_keys_tenant_active_idx"
            ),
        ),
        # Add RLS constraint for api_keys
        migrations.AddConstraint(
            model_name="apikey",
            constraint=RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_apikey",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
