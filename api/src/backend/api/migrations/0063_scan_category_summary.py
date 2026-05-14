import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.db_utils
import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0062_backfill_daily_severity_summaries"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScanCategorySummary",
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
                        related_name="category_summaries",
                        related_query_name="category_summary",
                        to="api.scan",
                    ),
                ),
                (
                    "category",
                    models.CharField(max_length=100),
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
            ],
            options={
                "db_table": "scan_category_summaries",
                "abstract": False,
            },
        ),
        migrations.AddIndex(
            model_name="scancategorysummary",
            index=models.Index(
                fields=["tenant_id", "scan"], name="scs_tenant_scan_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="scancategorysummary",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "scan_id", "category", "severity"),
                name="unique_category_severity_per_scan",
            ),
        ),
        migrations.AddConstraint(
            model_name="scancategorysummary",
            constraint=api.rls.RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_scancategorysummary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
