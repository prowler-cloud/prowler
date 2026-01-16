# Migration to add status field to Provider model
from django.db import migrations, models

from api.db_router import MainRouter


def populate_provider_status(apps, schema_editor):
    """
    Populate status field based on existing connected field values.

    Migration logic for production:
    - connected=True → status="connected" (successful connection)
    - connected=False → status="error" (connection was attempted but failed)
    - connected=NULL → status="pending" (never attempted to connect)
    """
    Provider = apps.get_model("api", "Provider")
    db_alias = MainRouter.admin_db

    Provider.objects.using(db_alias).filter(connected=True).update(status="connected")
    Provider.objects.using(db_alias).filter(connected=False).update(status="error")
    Provider.objects.using(db_alias).filter(connected__isnull=True).update(
        status="pending"
    )


def reverse_populate(apps, schema_editor):
    """
    Reverse the status population.
    """
    Provider = apps.get_model("api", "Provider")
    db_alias = MainRouter.admin_db

    Provider.objects.using(db_alias).all().update(status=None)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0067_tenant_compliance_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="provider",
            name="status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("pending", "Pending"),
                    ("checking", "Checking"),
                    ("connected", "Connected"),
                    ("error", "Error"),
                ],
                default="pending",
                max_length=20,
                null=True,
            ),
        ),
        migrations.RunPython(
            populate_provider_status,
            reverse_code=reverse_populate,
        ),
    ]
