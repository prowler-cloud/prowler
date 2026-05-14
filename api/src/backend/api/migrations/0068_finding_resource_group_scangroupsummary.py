import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.db_utils
import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0067_tenant_compliance_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="resource_groups",
            field=models.TextField(
                blank=True,
                help_text="Resource group from check metadata for efficient filtering",
                null=True,
            ),
        ),
        migrations.CreateModel(
            name="ScanGroupSummary",
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
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
                (
                    "inserted_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="resource_group_summaries",
                        related_query_name="resource_group_summary",
                        to="api.scan",
                    ),
                ),
                (
                    "resource_group",
                    models.CharField(max_length=50),
                ),
                (
                    "severity",
                    api.db_utils.SeverityEnumField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                            ("informational", "Informational"),
                        ],
                    ),
                ),
                (
                    "total_findings",
                    models.IntegerField(
                        default=0, help_text="Non-muted findings (PASS + FAIL)"
                    ),
                ),
                (
                    "failed_findings",
                    models.IntegerField(
                        default=0,
                        help_text="Non-muted FAIL findings (subset of total_findings)",
                    ),
                ),
                (
                    "new_failed_findings",
                    models.IntegerField(
                        default=0,
                        help_text="Non-muted FAIL with delta='new' (subset of failed_findings)",
                    ),
                ),
                (
                    "resources_count",
                    models.IntegerField(
                        default=0, help_text="Count of distinct resource_uid values"
                    ),
                ),
            ],
            options={
                "db_table": "scan_resource_group_summaries",
                "abstract": False,
            },
        ),
        migrations.AddIndex(
            model_name="scangroupsummary",
            index=models.Index(
                fields=["tenant_id", "scan"], name="srgs_tenant_scan_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="scangroupsummary",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "scan_id", "resource_group", "severity"),
                name="unique_resource_group_severity_per_scan",
            ),
        ),
        migrations.AddConstraint(
            model_name="scangroupsummary",
            constraint=api.rls.RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_scangroupsummary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
