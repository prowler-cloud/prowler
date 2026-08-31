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
                    "issue_type",
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
                    "attempt_state",
                    models.CharField(
                        choices=[
                            ("idle", "Idle"),
                            ("creating", "Creating"),
                            ("uncertain", "Uncertain"),
                            ("retryable_failure", "Retryable failure"),
                            ("terminal_failure", "Terminal failure"),
                        ],
                        default="idle",
                        max_length=32,
                    ),
                ),
                (
                    "claim_token",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("claim_expires_at", models.DateTimeField(blank=True, null=True)),
                (
                    "delivery_attempt_token",
                    models.UUIDField(blank=True, null=True),
                ),
                (
                    "attempt_operation",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("initial", "Initial"),
                            ("replacement", "Replacement"),
                        ],
                        max_length=16,
                        null=True,
                    ),
                ),
                (
                    "attempt_project_key",
                    models.CharField(blank=True, max_length=64, null=True),
                ),
                (
                    "attempt_issue_type",
                    models.CharField(blank=True, max_length=64, null=True),
                ),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("last_attempt_at", models.DateTimeField(blank=True, null=True)),
                (
                    "last_error_code",
                    models.CharField(blank=True, max_length=128, null=True),
                ),
                ("last_error_message", models.TextField(blank=True, null=True)),
                ("next_reconcile_at", models.DateTimeField(blank=True, null=True)),
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
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
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
                include=(
                    "id",
                    "finding_id",
                    "issue_id",
                    "issue_key",
                    "issue_status_category",
                    "attempt_state",
                    "claim_expires_at",
                ),
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
            constraint=models.UniqueConstraint(
                condition=models.Q(("issue_id__isnull", False)),
                fields=("tenant_id", "integration_id", "issue_id"),
                name="unique_jira_issue_identity",
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
                    ),
                    models.Q(
                        models.Q(
                            ("issue_id__isnull", False),
                            ("issue_key__isnull", False),
                            ("issue_url__isnull", False),
                        ),
                        models.Q(("issue_id", ""), _negated=True),
                        models.Q(("issue_key", ""), _negated=True),
                        models.Q(("issue_url", ""), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="jira_issue_link_all_or_none",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("claim_token__isnull", True),
                        ("claim_expires_at__isnull", True),
                    ),
                    models.Q(
                        ("claim_token__isnull", False),
                        ("claim_expires_at__isnull", False),
                        models.Q(("claim_token", ""), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="jira_issue_claim_all_or_none",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    (
                        "attempt_state__in",
                        (
                            "idle",
                            "creating",
                            "uncertain",
                            "retryable_failure",
                            "terminal_failure",
                        ),
                    )
                ),
                name="jira_issue_valid_attempt_state",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("attempt_operation__isnull", True),
                    ("attempt_operation__in", ("initial", "replacement")),
                    _connector="OR",
                ),
                name="jira_issue_valid_operation",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("attempt_state", "idle"),
                    models.Q(
                        ("delivery_attempt_token__isnull", False),
                        ("attempt_operation__isnull", False),
                        ("attempt_project_key__isnull", False),
                        ("attempt_issue_type__isnull", False),
                        models.Q(("attempt_project_key", ""), _negated=True),
                        models.Q(("attempt_issue_type", ""), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="jira_issue_attempt_fields",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("attempt_state", "creating"), _negated=True),
                    models.Q(
                        ("claim_token__isnull", False),
                        ("claim_expires_at__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="jira_issue_creating_has_claim",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("claim_token__isnull", True),
                    ("attempt_state", "creating"),
                    _connector="OR",
                ),
                name="jira_issue_claim_only_creating",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("attempt_operation", "replacement"), _negated=True),
                    ("issue_id__isnull", False),
                    _connector="OR",
                ),
                name="jira_issue_replacement_has_link",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissue",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("next_reconcile_at__isnull", True),
                    ("attempt_state", "uncertain"),
                    _connector="OR",
                ),
                name="jira_issue_reconcile_uncertain",
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
