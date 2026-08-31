import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0097_attack_paths_scan_db_defaults"),
    ]

    operations = [
        migrations.CreateModel(
            name="JiraIssue",
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
                ("finding_uid", models.CharField(max_length=300)),
                ("finding_id", models.UUIDField()),
                (
                    "issue_key",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "issue_id",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "issue_url",
                    models.URLField(blank=True, default="", max_length=2048),
                ),
                ("project_key", models.CharField(max_length=64)),
                (
                    "issue_status",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "issue_status_category",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("new", "New"),
                            ("indeterminate", "In progress"),
                            ("done", "Done"),
                        ],
                        default="",
                        max_length=16,
                    ),
                ),
                ("status_synced_at", models.DateTimeField(blank=True, null=True)),
                (
                    "integration",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="jira_issues",
                        to="api.integration",
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="jira_issues",
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
                "db_table": "jira_issues",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "integration_id", "provider_id", "finding_uid"),
                name="unique_jira_issue_per_finding",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_jiraissue",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
