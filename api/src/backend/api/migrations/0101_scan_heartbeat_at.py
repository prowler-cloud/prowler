from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="heartbeat_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
