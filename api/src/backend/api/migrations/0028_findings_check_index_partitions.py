from functools import partial

from django.db import migrations

from api.db_utils import create_index_on_partitions, drop_index_on_partitions


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0027_compliance_requirement_overviews"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_check_idx",
                columns="tenant_id, scan_id, check_id",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_check_idx",
            ),
        )
    ]
