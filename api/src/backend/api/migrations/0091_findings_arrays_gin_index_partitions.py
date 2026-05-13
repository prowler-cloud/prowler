from functools import partial

from django.db import migrations

from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0090_attack_paths_cleanup_priority"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_arrays_idx",
                columns="categories, resource_services, resource_regions, resource_types",
                method="GIN",
                all_partitions=True,
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="gin_find_arrays_idx",
            ),
        )
    ]
