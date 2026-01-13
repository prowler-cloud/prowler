from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0068_finding_resource_group_scangroupsummary"),
    ]

    operations = [
        migrations.AddField(
            model_name="resource",
            name="group",
            field=models.TextField(
                blank=True,
                help_text="Group for categorization (e.g., compute, storage, IAM)",
                null=True,
            ),
        ),
    ]
