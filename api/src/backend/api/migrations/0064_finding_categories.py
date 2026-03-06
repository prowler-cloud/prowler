import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0063_scan_category_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="categories",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(max_length=100),
                blank=True,
                null=True,
                size=None,
                help_text="Categories from check metadata for efficient filtering",
            ),
        ),
    ]
