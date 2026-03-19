from django.db import migrations


TASK_NAME = "attack-paths-cleanup-stale-scans"
INTERVAL_HOURS = 24


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=INTERVAL_HOURS,
        period="hours",
    )

    PeriodicTask.objects.create(
        name=TASK_NAME,
        task=TASK_NAME,
        interval=schedule,
        enabled=True,
    )


def delete_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=TASK_NAME).delete()

    # Clean up the schedule if no other task references it
    IntervalSchedule.objects.filter(
        every=INTERVAL_HOURS,
        period="hours",
        periodictask=None,
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0084_googleworkspace_provider"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
