from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0087_vercel_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="findinggroupdailysummary",
            name="manual_count",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="findinggroupdailysummary",
            name="muted",
            field=models.BooleanField(default=False),
        ),
    ]
