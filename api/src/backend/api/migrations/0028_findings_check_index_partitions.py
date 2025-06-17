from django.db import migrations

from api.operations import CreatePartitionedIndex


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0027_compliance_requirement_overviews"),
    ]

    operations = [
        CreatePartitionedIndex(
            parent_table="findings",
            index_name="find_tenant_scan_check_idx",
            columns="tenant_id, scan_id, check_id",
            method="BTREE",
            all_partitions=False,
            create_parent_index=True,
        )
    ]
