# TODO: drop after Neptune cutover
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0090_attack_paths_cleanup_priority"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackpathsscan",
            name="is_neptune",
            field=models.BooleanField(default=False),
        ),
    ]
