import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0034_processors"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="muted_reason",
            field=models.TextField(
                blank=True,
                max_length=500,
                null=True,
                validators=[django.core.validators.MinLengthValidator(3)],
            ),
        ),
    ]
