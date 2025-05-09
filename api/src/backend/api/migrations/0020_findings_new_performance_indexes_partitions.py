from functools import partial

from django.db import migrations

from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0019_finding_denormalize_resource_fields"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_service_idx",
                columns="resource_services",
                method="GIN",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_service_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_region_idx",
                columns="resource_regions",
                method="GIN",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_region_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_rtype_idx",
                columns="resource_types",
                method="GIN",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_rtype_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="findings_uid_idx",
            ),
            reverse_code=partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="findings_uid_idx",
                columns="uid",
                method="BTREE",
            ),
        ),
        migrations.RunPython(
            partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="findings_filter_idx",
            ),
            reverse_code=partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="findings_filter_idx",
                columns="scan_id, impact, severity, status, check_id, delta",
                method="BTREE",
            ),
        ),
    ]
