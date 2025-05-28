# Generated manually for adding new_uid field to Finding model

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0026_provider_secret_gcp_service_account"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="new_uid",
            field=models.TextField(blank=True, null=True),
        ),
    ]
