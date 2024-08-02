import uuid

from django.conf import settings
from django.db import migrations, models

DB_NAME = settings.DATABASES["default"]["NAME"]
DB_USER_NAME = settings.DATABASES["default"]["USER"]
DB_USER_PASSWORD = settings.DATABASES["default"]["PASSWORD"]


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.RunSQL(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT
                    FROM   pg_catalog.pg_roles
                    WHERE  rolname = '{DB_USER_NAME}') THEN
                    CREATE ROLE {DB_USER_NAME} LOGIN PASSWORD '{DB_USER_PASSWORD}';
                END IF;
            END
            $$;
            """
        ),
        migrations.RunSQL(
            # `runserver` command for dev tools requires read access to migrations
            f"""
            GRANT CONNECT ON DATABASE "{DB_NAME}" TO {DB_USER_NAME};
            GRANT SELECT ON django_migrations TO {DB_USER_NAME};
            """
        ),
        migrations.CreateModel(
            name="Tenant",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=100)),
            ],
            options={
                "db_table": "tenant",
            },
        ),
        migrations.RunSQL(
            # Needed for now since we don't have users yet
            f"""
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant TO {DB_USER_NAME};
            """
        ),
    ]
