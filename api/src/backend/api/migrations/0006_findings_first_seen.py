from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_rbac_missing_admin_roles"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="first_seen_at",
            field=models.DateTimeField(editable=False, null=True),
        ),
    ]
