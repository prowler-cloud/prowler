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
                    "issue_id",
                    models.CharField(blank=True, max_length=64, null=True),
                ),
                (
                    "issue_key",
                    models.CharField(blank=True, max_length=64, null=True),
                ),
                (
                    "issue_url",
                    models.URLField(blank=True, max_length=2048, null=True),
                ),
                (
                    "project_key",
                    models.CharField(blank=True, max_length=64, null=True),
                ),
                (
                    "issue_status",
                    models.CharField(blank=True, max_length=64, null=True),
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
                        max_length=16,
                        null=True,
                    ),
                ),
                ("status_synced_at", models.DateTimeField(blank=True, null=True)),
                (
                    "delivery_attempt_token",
                    models.UUIDField(blank=True, null=True),
                ),
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
            constraint=models.UniqueConstraint(
                condition=models.Q(("delivery_attempt_token__isnull", False)),
                fields=("delivery_attempt_token",),
                name="unique_jira_delivery_attempt",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("issue_id__isnull", True),
                        ("issue_key__isnull", True),
                        ("issue_url__isnull", True),
                        ("project_key__isnull", True),
                    ),
                    models.Q(
                        models.Q(
                            ("issue_id__isnull", False),
                            ("issue_key__isnull", False),
                            ("issue_url__isnull", False),
                            ("project_key__isnull", False),
                        ),
                        models.Q(("issue_id", ""), _negated=True),
                        models.Q(("issue_key", ""), _negated=True),
                        models.Q(("issue_url", ""), _negated=True),
                        models.Q(("project_key", ""), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="jira_issue_link_all_or_none",
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
