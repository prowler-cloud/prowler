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
                name="ji_tenant_prov_uid_int_idx",
            ),
        ),
    ]
