import uuid

import django.contrib.postgres.fields
import django.db.models.deletion
from django.db import migrations, models

import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0061_daily_severity_summary"),
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
                    "tenant_id",
                    models.UUIDField(db_index=True, editable=False),
                ),
                (
                    "scan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.scan",
                    ),
                ),
                (
                    "categories",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=100),
                        default=list,
                        size=None,
                    ),
                ),
            ],
            options={
                "db_table": "scan_category_summaries",
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
            constraint=api.rls.RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_scancategorysummary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
