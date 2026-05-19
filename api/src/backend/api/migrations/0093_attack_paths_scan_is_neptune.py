# TODO: drop after Neptune cutover
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0092_findings_arrays_gin_index_parent"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackpathsscan",
            name="is_neptune",
            field=models.BooleanField(default=False),
        ),
    ]
