import django.contrib.postgres.indexes
from django.contrib.postgres.operations import (
    AddIndexConcurrently,
    RemoveIndexConcurrently,
)
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0020_findings_new_performance_indexes_partitions"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="finding",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["resource_services"], name="gin_find_service_idx"
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["resource_regions"], name="gin_find_region_idx"
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["resource_types"], name="gin_find_rtype_idx"
            ),
        ),
        RemoveIndexConcurrently(
            model_name="finding",
            name="findings_uid_idx",
        ),
        RemoveIndexConcurrently(
            model_name="finding",
            name="findings_filter_idx",
        ),
    ]
