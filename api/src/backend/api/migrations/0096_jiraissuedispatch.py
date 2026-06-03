import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0095_reconcile_orphan_tasks_periodic_task"),
    ]

    operations = [
        migrations.CreateModel(
            name="JiraIssueDispatch",
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
                ("finding_id", models.UUIDField()),
                (
                    "integration",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="jira_dispatches",
                        to="api.integration",
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
                "db_table": "jira_issue_dispatches",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="jiraissuedispatch",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "integration_id", "finding_id"),
                name="unique_jira_issue_dispatch",
            ),
        ),
        migrations.AddConstraint(
            model_name="jiraissuedispatch",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_jiraissuedispatch",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
