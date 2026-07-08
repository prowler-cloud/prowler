from django.db import migrations

TASK_NAME = "attack-paths-cleanup-stale-scans"


def set_cleanup_priority(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).update(priority=0)


def unset_cleanup_priority(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).update(priority=None)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0089_backfill_finding_group_status_muted"),
    ]

    operations = [
        migrations.RunPython(set_cleanup_priority, unset_cleanup_priority),
    ]
