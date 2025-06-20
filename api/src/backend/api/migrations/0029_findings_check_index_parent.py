from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0028_findings_check_index_partitions"),
    ]

    operations = [
        # No-op: Index managed manually via CratePartitionedIndex in the previous migrations
        # Deprecated
    ]
