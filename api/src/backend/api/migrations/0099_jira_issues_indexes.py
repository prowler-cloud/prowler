from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0098_jira_issues"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="jiraissue",
            index=models.Index(
                fields=["tenant_id", "provider_id", "finding_uid", "integration_id"],
                include=[
                    "id",
                    "finding_id",
                    "issue_id",
                    "issue_key",
                    "issue_status_category",
                    "attempt_state",
                ],
                name="ji_ui_lookup_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="jiraissue",
            index=models.Index(
                condition=models.Q(
                    ("attempt_state", "creating"),
                    ("claim_expires_at__isnull", False),
                ),
                fields=["tenant_id", "claim_expires_at"],
                include=["id"],
                name="ji_stale_claim_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="jiraissue",
            index=models.Index(
                condition=models.Q(
                    ("attempt_state", "uncertain"),
                    ("next_reconcile_at__isnull", False),
                ),
                fields=["tenant_id", "next_reconcile_at"],
                include=["id"],
                name="ji_reconcile_due_idx",
            ),
        ),
    ]
