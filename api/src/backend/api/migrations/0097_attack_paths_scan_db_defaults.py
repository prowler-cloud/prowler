from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0096_attack_paths_scan_is_migrated"),
    ]

    operations = [
        migrations.AlterField(
            model_name="attackpathsscan",
            name="is_migrated",
            field=models.BooleanField(db_default=False, default=False),
        ),
        migrations.AlterField(
            model_name="attackpathsscan",
            name="sink_backend",
            field=models.CharField(
                choices=[("neo4j", "Neo4j"), ("neptune", "Neptune")],
                db_default="neo4j",
                default="neo4j",
                max_length=16,
            ),
        ),
    ]
