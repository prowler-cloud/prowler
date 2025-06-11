import uuid

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models

from api.rls import RowLevelSecurityConstraint


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0025_processors"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="muted_reason",
            field=models.TextField(
                blank=True,
                max_length=500,
                null=True,
                validators=[django.core.validators.MinLengthValidator(3)],
            ),
        ),
        migrations.CreateModel(
            name="MutedFinding",
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
                ("finding_uid", models.TextField(max_length=300)),
                ("check_id", models.CharField(max_length=100)),
                ("service", models.CharField(max_length=100)),
                ("region", models.CharField(max_length=100)),
                ("resource_type", models.CharField(max_length=100)),
                (
                    "reason",
                    models.TextField(
                        blank=True,
                        max_length=500,
                        null=True,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="muted_findings",
                        related_query_name="muted_finding",
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
                "db_table": "muted_findings",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "provider_id"],
                        name="mf_tenant_provider_idx",
                    ),
                    models.Index(
                        fields=["tenant_id", "finding_uid"], name="mf_tenant_uid_idx"
                    ),
                    models.Index(
                        fields=["tenant_id", "check_id"], name="mf_tenant_check_idx"
                    ),
                    models.Index(
                        fields=["tenant_id", "service"], name="mf_tenant_service_idx"
                    ),
                    models.Index(
                        fields=["tenant_id", "region"], name="mf_tenant_region_idx"
                    ),
                    models.Index(
                        fields=["tenant_id", "resource_type"],
                        name="mf_tenant_resource_type_idx",
                    ),
                ],
                "unique_together": {("tenant_id", "provider", "finding_uid")},
            },
        ),
        migrations.AddConstraint(
            model_name="mutedfinding",
            constraint=RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_mutedfinding",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
