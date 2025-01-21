from django.conf import settings
from django.db import migrations

from api.db_utils import DB_PROWLER_USER

DB_NAME = settings.DATABASES["default"]["NAME"]


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0006_findings_first_seen"),
        ("socialaccount", "0006_alter_socialaccount_extra_data"),
        ("authtoken", "0004_alter_tokenproxy_options"),
    ]

    operations = [
        migrations.RunSQL(
            f"""
            GRANT SELECT, INSERT, UPDATE, DELETE ON socialaccount_socialapp TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON socialaccount_socialaccount TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON socialaccount_socialtoken TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON account_emailaddress TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON account_emailconfirmation TO {DB_PROWLER_USER};
            GRANT SELECT, INSERT, UPDATE, DELETE ON authtoken_token TO {DB_PROWLER_USER};
            """
        ),
    ]
