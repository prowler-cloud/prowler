from functools import partial

from api.db_utils import create_index_on_partitions, drop_index_on_partitions
from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0023_resources_lookup_optimization"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_uid_inserted_idx",
                columns="tenant_id, uid, inserted_at DESC",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_uid_inserted_idx",
            ),
        )
    ]
