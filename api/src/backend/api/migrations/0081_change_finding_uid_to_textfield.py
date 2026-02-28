# Generated migration to change Finding.uid from CharField(max_length=300) to TextField()

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0080_backfill_attack_paths_graph_data_ready"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="uid",
            field=models.TextField(),
        ),
    ]
