import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.db_utils
import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0065_alibabacloud_provider"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProviderComplianceScore",
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
                ("requirement_id", models.TextField()),
                (
                    "requirement_status",
                    api.db_utils.StatusEnumField(
                        choices=[
                            ("FAIL", "Fail"),
                            ("PASS", "Pass"),
                            ("MANUAL", "Manual"),
                        ]
                    ),
                ),
                ("scan_completed_at", models.DateTimeField()),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="compliance_scores",
                        related_query_name="compliance_score",
                        to="api.provider",
                    ),
                ),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="compliance_scores",
                        related_query_name="compliance_score",
                        to="api.scan",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "provider_compliance_scores",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="providercompliancescore",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider_id", "compliance_id", "requirement_id"),
                name="unique_provider_compliance_req",
            ),
        ),
        migrations.AddConstraint(
            model_name="providercompliancescore",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_providercompliancescore",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="providercompliancescore",
            index=models.Index(
                fields=["tenant_id", "provider_id", "compliance_id"],
                name="pcs_tenant_prov_comp_idx",
            ),
        ),
    ]
