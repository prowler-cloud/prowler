from django.db import migrations, models


def alter_finding_uid_to_text(apps, schema_editor):
    """
    Change findings.uid from varchar(300) to text on both the parent table and
    all existing partitions.

    PostgreSQL does not rewrite rows when relaxing a varchar constraint to text
    (both types share the same underlying varlena storage), so this is a
    metadata-only operation that keeps the ACCESS EXCLUSIVE lock duration
    minimal.
    """
    with schema_editor.connection.cursor() as cursor:
        # Alter the parent table; PostgreSQL 11+ cascades the type change to
        # every partition automatically.
        cursor.execute(
            "ALTER TABLE findings ALTER COLUMN uid TYPE text"
        )


def revert_finding_uid_to_varchar(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE findings ALTER COLUMN uid TYPE varchar(300)"
        )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0092_findings_arrays_gin_index_parent"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="finding",
                    name="uid",
                    field=models.TextField(),
                ),
            ],
            database_operations=[
                migrations.RunPython(
                    alter_finding_uid_to_text,
                    reverse_code=revert_finding_uid_to_varchar,
                ),
            ],
        ),
    ]
