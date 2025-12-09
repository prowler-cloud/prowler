from django.contrib.postgres.operations import CreateExtension
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0061_daily_severity_summary"),
    ]

    operations = [
        CreateExtension("btree_gin"),
    ]
