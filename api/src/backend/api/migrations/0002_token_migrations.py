from django.conf import settings
from django.db import migrations

from api.db_utils import DB_PROWLER_USER

DB_NAME = settings.DATABASES["default"]["NAME"]


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0001_initial"),
        ("token_blacklist", "0012_alter_outstandingtoken_user"),
    ]

    operations = [
        migrations.RunSQL(
            f"""
            GRANT SELECT, INSERT, UPDATE, DELETE ON token_blacklist_blacklistedtoken TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON token_blacklist_outstandingtoken TO {DB_PROWLER_USER};
            GRANT SELECT, DELETE ON django_admin_log TO {DB_PROWLER_USER};
            """
        ),
    ]
