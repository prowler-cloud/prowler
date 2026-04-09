from django.db import migrations
from tasks.tasks import backfill_finding_group_summaries_task

from api.db_router import MainRouter
from api.rls import Tenant


def trigger_backfill_task(apps, schema_editor):
    """
    Re-dispatch the finding-group backfill task for every tenant so the new
    `manual_count` and `muted` columns added in 0088 get populated from the
    last 10 days of completed scans.

    The aggregator (`aggregate_finding_group_summaries`) recomputes every
    column on each call, so it back-populates the new fields without touching
    the existing ones beyond a normal upsert.
    """
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)

    for tenant_id in tenant_ids:
        backfill_finding_group_summaries_task.delay(tenant_id=str(tenant_id), days=10)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0088_finding_group_status_muted_fields"),
    ]

    operations = [
        migrations.RunPython(trigger_backfill_task, migrations.RunPython.noop),
    ]
