import json
import uuid
from datetime import timezone as datetime_timezone

import django.db.models.deletion
from django.db import migrations, models

import api.rls
import api.validators


def _build_daily_cron_expression(start_time):
    if start_time is None:
        return "0 0 * * *"

    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=datetime_timezone.utc)

    start_time_utc = start_time.astimezone(datetime_timezone.utc)
    return f"{start_time_utc.minute} {start_time_utc.hour} * * *"


def backfill_legacy_daily_scan_schedules(apps, schema_editor):  # noqa: ARG001
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    Provider = apps.get_model("api", "Provider")
    Scan = apps.get_model("api", "Scan")
    ScanSchedule = apps.get_model("api", "ScanSchedule")

    for periodic_task in (
        PeriodicTask.objects.filter(task="scan-perform-scheduled", enabled=True)
        .order_by("-date_changed", "-id")
        .iterator()
    ):
        kwargs = periodic_task.kwargs or ""
        try:
            task_kwargs = json.loads(kwargs)
        except (TypeError, json.JSONDecodeError):
            continue

        if not isinstance(task_kwargs, dict):
            continue

        tenant_id_raw = task_kwargs.get("tenant_id")
        provider_id_raw = task_kwargs.get("provider_id")
        if not tenant_id_raw or not provider_id_raw:
            continue

        try:
            tenant_id = uuid.UUID(str(tenant_id_raw))
            provider_id = uuid.UUID(str(provider_id_raw))
        except (TypeError, ValueError, AttributeError):
            continue

        provider = Provider.objects.filter(
            id=provider_id,
            tenant_id=tenant_id,
            is_deleted=False,
        ).first()

        if provider is None:
            continue

        # Preserve a single active migrated schedule per provider.
        if provider.scan_schedule_id:
            continue

        scan_schedule = ScanSchedule.objects.create(
            tenant_id=tenant_id,
            cron_expression=_build_daily_cron_expression(periodic_task.start_time),
            enabled=True,
            scheduler_task_id=periodic_task.id,
        )

        Provider.objects.filter(id=provider_id, tenant_id=tenant_id).update(
            scan_schedule_id=scan_schedule.id
        )

        Scan.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            scheduler_task_id=periodic_task.id,
            trigger="scheduled",
        ).update(scan_schedule_id=scan_schedule.id)


def noop_reverse(apps, schema_editor):  # noqa: ARG001
    """Forward-only data migration."""


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0078_remove_attackpathsscan_graph_database_fields"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScanSchedule",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "cron_expression",
                    models.CharField(
                        max_length=100,
                        validators=[api.validators.cron_5_fields_validator],
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                (
                    "scheduler_task",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="django_celery_beat.periodictask",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "scan_schedules",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="scanschedule",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scanschedule",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="scanschedule",
            index=models.Index(
                fields=["tenant_id", "enabled"],
                name="scansch_tenant_enabled_idx",
            ),
        ),
        migrations.AddField(
            model_name="provider",
            name="scan_schedule",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="providers",
                to="api.scanschedule",
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="scan_schedule",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="scans",
                related_query_name="scan",
                to="api.scanschedule",
            ),
        ),
        migrations.RunPython(
            code=backfill_legacy_daily_scan_schedules,
            reverse_code=noop_reverse,
        ),
    ]
