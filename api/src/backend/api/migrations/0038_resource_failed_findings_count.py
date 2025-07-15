from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0037_rfm_tenant_finding_index_parent"),
    ]

    operations = [
        migrations.AddField(
            model_name="resource",
            name="failed_findings_count",
            field=models.IntegerField(default=0),
        )
    ]
