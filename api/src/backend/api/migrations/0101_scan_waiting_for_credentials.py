from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0100_attack_paths_tmp_db_reap_periodic_task")]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="waiting_for_credentials",
            field=models.BooleanField(default=False),
        ),
    ]
