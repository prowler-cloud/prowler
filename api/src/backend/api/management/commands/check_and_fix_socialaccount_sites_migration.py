from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS, connection, connections, transaction
from django.db.migrations.recorder import MigrationRecorder


def table_exists(table_name):
    with connection.cursor() as cursor:
        cursor.execute(
            """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = %s
                )
            """,
            [table_name],
        )
        return cursor.fetchone()[0]


class Command(BaseCommand):
    help = "Fix migration inconsistency between socialaccount and sites"

    def add_arguments(self, parser):
        parser.add_argument(
            "--database",
            default=DEFAULT_DB_ALIAS,
            help="Specifies the database to operate on.",
        )

    def handle(self, *args, **options):
        db = options["database"]
        connection = connections[db]
        recorder = MigrationRecorder(connection)

        applied = set(recorder.applied_migrations())

        has_social = ("socialaccount", "0001_initial") in applied

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'django_site'
                );
            """
            )
            site_table_exists = cursor.fetchone()[0]

        if has_social and not site_table_exists:
            self.stdout.write(
                f"Detected inconsistency in '{db}'. Creating 'django_site' table manually..."
            )

            with transaction.atomic(using=db):
                with connection.schema_editor() as schema_editor:
                    schema_editor.create_model(Site)

                recorder.record_applied("sites", "0001_initial")
                recorder.record_applied("sites", "0002_alter_domain_unique")

            self.stdout.write(
                "Fixed: 'django_site' table created and migrations registered."
            )

            # Ensure the relationship table also exists
            if not table_exists("socialaccount_socialapp_sites"):
                self.stdout.write(
                    "Detected missing 'socialaccount_socialapp_sites' table. Creating manually..."
                )
                with connection.schema_editor() as schema_editor:
                    from allauth.socialaccount.models import SocialApp

                    schema_editor.create_model(
                        SocialApp._meta.get_field("sites").remote_field.through
                    )
                self.stdout.write(
                    "Fixed: 'socialaccount_socialapp_sites' table created."
                )
