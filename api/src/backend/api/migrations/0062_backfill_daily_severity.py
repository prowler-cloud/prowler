from datetime import timedelta

from django.db import migrations
from django.utils import timezone

from api.db_router import MainRouter


def backfill_daily_severity(apps, schema_editor):
    """Backfill DailyFindingsSeverity for all tenants with 90 days of historical data."""
    Tenant = apps.get_model("api", "Tenant")

    # Use schema_editor.connection to get the correct database connection
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("SELECT EXISTS(SELECT 1 FROM daily_findings_severity LIMIT 1)")
        if cursor.fetchone()[0]:
            return

    days = 90
    cutoff_date = (timezone.now() - timedelta(days=days)).date()
    tenants = list(
        Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    )

    if not tenants:
        return

    backfill_sql = """
        WITH last_scan_per_day AS (
            SELECT DISTINCT ON (s.tenant_id, s.provider_id, DATE(s.completed_at))
                s.tenant_id,
                s.provider_id,
                s.id as scan_id,
                DATE(s.completed_at) as snapshot_date
            FROM scans s
            WHERE s.tenant_id = %s
              AND s.completed_at >= %s
              AND s.state = 'completed'
            ORDER BY s.tenant_id, s.provider_id, DATE(s.completed_at), s.completed_at DESC
        ),
        aggregated AS (
            SELECT
                ls.tenant_id,
                ls.provider_id,
                ls.scan_id,
                ls.snapshot_date,
                p.provider as provider_type,
                COALESCE(SUM(CASE WHEN ss.severity::text = 'critical' THEN ss.fail ELSE 0 END), 0) as critical,
                COALESCE(SUM(CASE WHEN ss.severity::text = 'high' THEN ss.fail ELSE 0 END), 0) as high,
                COALESCE(SUM(CASE WHEN ss.severity::text = 'medium' THEN ss.fail ELSE 0 END), 0) as medium,
                COALESCE(SUM(CASE WHEN ss.severity::text = 'low' THEN ss.fail ELSE 0 END), 0) as low,
                COALESCE(SUM(CASE WHEN ss.severity::text = 'informational' THEN ss.fail ELSE 0 END), 0) as informational,
                COALESCE(SUM(ss.muted), 0) as muted
            FROM last_scan_per_day ls
            JOIN providers p ON ls.provider_id = p.id
            LEFT JOIN scan_summaries ss ON ls.scan_id = ss.scan_id AND ls.tenant_id = ss.tenant_id
            GROUP BY ls.tenant_id, ls.provider_id, ls.scan_id, ls.snapshot_date, p.provider
        )
        INSERT INTO daily_findings_severity (
            id, tenant_id, provider_id, scan_id, date, provider_type,
            critical, high, medium, low, informational, muted,
            inserted_at, updated_at
        )
        SELECT
            gen_random_uuid(),
            tenant_id,
            provider_id,
            scan_id,
            snapshot_date,
            provider_type,
            critical,
            high,
            medium,
            low,
            informational,
            muted,
            NOW(),
            NOW()
        FROM aggregated
        ON CONFLICT (tenant_id, provider_id, date)
        DO UPDATE SET
            scan_id = EXCLUDED.scan_id,
            provider_type = EXCLUDED.provider_type,
            critical = EXCLUDED.critical,
            high = EXCLUDED.high,
            medium = EXCLUDED.medium,
            low = EXCLUDED.low,
            informational = EXCLUDED.informational,
            muted = EXCLUDED.muted,
            updated_at = NOW()
    """

    with schema_editor.connection.cursor() as cursor:
        for tenant_id in tenants:
            cursor.execute(backfill_sql, [str(tenant_id), cutoff_date])


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0061_dailyfindingsseverity"),
    ]

    operations = [
        migrations.RunPython(
            backfill_daily_severity,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
