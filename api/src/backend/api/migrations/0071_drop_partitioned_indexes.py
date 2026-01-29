from django.db import migrations


class Migration(migrations.Migration):
    """
    Drop unused indexes on partitioned tables (findings, resource_finding_mappings).

    NOTE: RemoveIndexConcurrently cannot be used on partitioned tables in PostgreSQL.
    Standard RemoveIndex drops the parent index, which cascades to all partitions.
    """

    dependencies = [
        ("api", "0070_attack_paths_scan"),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name="finding",
            name="gin_findings_search_idx",
        ),
        migrations.RemoveIndex(
            model_name="finding",
            name="gin_find_service_idx",
        ),
        migrations.RemoveIndex(
            model_name="finding",
            name="gin_find_region_idx",
        ),
        migrations.RemoveIndex(
            model_name="finding",
            name="gin_find_rtype_idx",
        ),
        migrations.RemoveIndex(
            model_name="finding",
            name="find_delta_new_idx",
        ),
        migrations.RemoveIndex(
            model_name="resourcefindingmapping",
            name="rfm_tenant_finding_idx",
        ),
    ]
