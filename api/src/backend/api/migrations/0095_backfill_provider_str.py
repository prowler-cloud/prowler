from django.db import migrations
from tasks.tasks import backfill_provider_str_task

from api.db_router import MainRouter


def trigger_provider_str_backfill(apps, _schema_editor):
    """Dispatch a per-tenant Celery task to populate the transitional
    `provider_str` shadow column for rows created before the sync trigger
    from 0094 existed.

    New writes are already covered by the trigger, so this only fills the gap
    left by pre-existing rows. The work runs in the background, batched per
    tenant, so the migration itself finishes in seconds regardless of table
    size.
    """
    Tenant = apps.get_model("api", "Tenant")
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)

    for tenant_id in tenant_ids:
        backfill_provider_str_task.delay(tenant_id=str(tenant_id))


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0094_provider_str_shadow_column"),
    ]

    operations = [
        migrations.RunPython(trigger_provider_str_backfill, migrations.RunPython.noop),
    ]
