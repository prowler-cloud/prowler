from functools import partial

from django.db import migrations

from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0072_drop_unused_indexes"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_fail_new_idx",
                columns="tenant_id, scan_id",
                where="status = 'FAIL' AND delta = 'new'",
                all_partitions=True,
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_fail_new_idx",
            ),
        )
    ]
