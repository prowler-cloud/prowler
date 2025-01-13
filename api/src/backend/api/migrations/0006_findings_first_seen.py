from django.db import migrations, models


def populate_first_seen(apps, schema_editor):
    # First, update findings where delta='new'
    schema_editor.execute(
        """
        UPDATE findings
        SET first_seen = inserted_at
        WHERE delta = 'new';
    """
    )

    # Then update all other findings
    schema_editor.execute(
        """
        UPDATE findings f1
        SET first_seen = (
            SELECT MIN(f2.inserted_at)
            FROM findings f2
            WHERE f2.uid = f1.uid
            AND f2.delta = 'new'
        )
        WHERE f1.delta != 'new' OR f1.delta IS NULL;
    """
    )

    # Handle any remaining NULL values (fallback to inserted_at)
    schema_editor.execute(
        """
        UPDATE findings
        SET first_seen = inserted_at
        WHERE first_seen IS NULL;
    """
    )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_rbac_missing_admin_roles"),
    ]

    operations = [
        # Add first_seen field as nullable initially
        migrations.AddField(
            model_name="finding",
            name="first_seen",
            field=models.DateTimeField(null=True),
        ),
        # Populate the data
        migrations.RunPython(populate_first_seen),
        # Only after population, make it non-nullable
        migrations.AlterField(
            model_name="finding",
            name="first_seen",
            field=models.DateTimeField(editable=False),
        ),
    ]
