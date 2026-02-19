# Separate from 0079 because psqlextra's schema editor runs AddField DDL and DML
# on different database connections, causing a deadlock when combined with RunPython
# in the same migration.

from django.db import migrations

from api.db_router import MainRouter


def backfill_graph_data_ready(apps, schema_editor):
    """Set graph_data_ready=True for all completed AttackPathsScan rows."""
    AttackPathsScan = apps.get_model("api", "AttackPathsScan")
    AttackPathsScan.objects.using(MainRouter.admin_db).filter(
        state="completed",
        graph_data_ready=False,
    ).update(graph_data_ready=True)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0079_attackpathsscan_graph_data_ready"),
    ]

    operations = [
        migrations.RunPython(backfill_graph_data_ready, migrations.RunPython.noop),
    ]
