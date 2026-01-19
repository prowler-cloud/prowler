from django.contrib.postgres.fields import ArrayField
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0068_finding_resource_group_scangroupsummary"),
    ]

    operations = [
        migrations.AddField(
            model_name="resource",
            name="groups",
            field=ArrayField(
                models.CharField(max_length=100),
                blank=True,
                help_text="Groups for categorization (e.g., compute, storage, IAM)",
                null=True,
            ),
        ),
    ]
