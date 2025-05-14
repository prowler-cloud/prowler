from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0011_findings_performance_indexes_parent"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="output_location",
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
