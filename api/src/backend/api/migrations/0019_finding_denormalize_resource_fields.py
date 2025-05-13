import django.contrib.postgres.fields
import django.contrib.postgres.indexes
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0018_resource_scan_summaries"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="resource_regions",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(max_length=100),
                blank=True,
                null=True,
                size=None,
            ),
        ),
        migrations.AddField(
            model_name="finding",
            name="resource_services",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(max_length=100),
                blank=True,
                null=True,
                size=None,
            ),
        ),
        migrations.AddField(
            model_name="finding",
            name="resource_types",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(max_length=100),
                blank=True,
                null=True,
                size=None,
            ),
        ),
    ]
