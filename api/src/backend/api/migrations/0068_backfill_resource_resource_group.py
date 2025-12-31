from django.db import migrations


class Migration(migrations.Migration):
    """
    Backfill resource_group for existing resources from their associated findings.

    This migration updates the resource_group field on resources by joining with
    the resource_finding_mappings and findings tables to get the resource_group
    from the most recent finding for each resource.
    """

    dependencies = [
        ("api", "0067_resource_resource_group"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            UPDATE resources r
            SET resource_group = subq.resource_group
            FROM (
                SELECT DISTINCT ON (rfm.resource_id)
                    rfm.resource_id,
                    f.resource_group
                FROM resource_finding_mappings rfm
                JOIN findings f ON f.id = rfm.finding_id AND f.tenant_id = rfm.tenant_id
                WHERE f.resource_group IS NOT NULL
                ORDER BY rfm.resource_id, f.inserted_at DESC
            ) subq
            WHERE r.id = subq.resource_id
            AND r.resource_group IS NULL;
            """,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
