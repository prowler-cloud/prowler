# Migration to add available field to Provider model
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0067_tenant_compliance_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="provider",
            name="available",
            field=models.BooleanField(
                default=True,
                help_text="Whether the provider account still exists. If False, connection checks are skipped.",
            ),
        ),
    ]
