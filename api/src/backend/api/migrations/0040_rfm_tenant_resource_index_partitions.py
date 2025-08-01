from functools import partial

from django.db import migrations

from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0039_resource_resources_failed_findings_idx"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="resource_finding_mappings",
                index_name="rfm_tenant_resource_idx",
                columns="tenant_id, resource_id",
                method="BTREE",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="resource_finding_mappings",
                index_name="rfm_tenant_resource_idx",
            ),
        ),
    ]
