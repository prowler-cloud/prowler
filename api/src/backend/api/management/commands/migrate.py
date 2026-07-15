from config.env import env
from django.core.management.commands.migrate import Command as MigrateCommand
from django.db import connections

# Any value Postgres accepts for lock_timeout ("5s", "500ms", ...). "0" disables
# it, the escape hatch for a release whose DDL is expected to wait.
MIGRATION_LOCK_TIMEOUT = env.str("DJANGO_MIGRATION_LOCK_TIMEOUT", default="5s")

SET_LOCK_TIMEOUT_QUERY = "SELECT set_config('lock_timeout', %s, FALSE);"


class Command(MigrateCommand):
    help = (
        f"{MigrateCommand.help} Applies lock_timeout to the migration session so DDL "
        "blocked on a lock fails instead of queueing every later reader behind it."
    )

    def handle(self, *args, **options):
        connection = connections[options["database"]]

        # is_local=FALSE keeps the setting alive across each migration's own
        # transaction. Unlike the RLS tenant variable this is safe to leave on the
        # session: migrate owns its connection for the life of the process and
        # never returns it to a pool.
        with connection.cursor() as cursor:
            cursor.execute(SET_LOCK_TIMEOUT_QUERY, [MIGRATION_LOCK_TIMEOUT])

        return super().handle(*args, **options)
