import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0066_provider_compliance_score"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantComplianceSummary",
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
                ("compliance_id", models.TextField()),
                ("requirements_passed", models.IntegerField(default=0)),
                ("requirements_failed", models.IntegerField(default=0)),
                ("requirements_manual", models.IntegerField(default=0)),
                ("total_requirements", models.IntegerField(default=0)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "tenant_compliance_summaries",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="tenantcompliancesummary",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "compliance_id"),
                name="unique_tenant_compliance_summary",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantcompliancesummary",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_tenantcompliancesummary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
