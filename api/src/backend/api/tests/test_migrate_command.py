from unittest.mock import Mock, patch

import psycopg2
import pytest
from django.core.management import call_command
from django.core.management.commands.migrate import Command as DjangoMigrateCommand
from django.db import DEFAULT_DB_ALIAS, OperationalError, connections
from django.db.migrations import Migration
from django.db.migrations.operations.special import RunSQL
from django.db.migrations.state import ProjectState


def _show_lock_timeout(alias: str = DEFAULT_DB_ALIAS) -> str:
    with connections[alias].cursor() as cursor:
        cursor.execute("SHOW lock_timeout;")
        return cursor.fetchone()[0]


@pytest.mark.django_db
class TestMigrateLockTimeout:
    def test_api_migrate_command_shadows_django_builtin(self):
        from django.core.management import get_commands

        assert get_commands()["migrate"] == "api"

    def test_lock_timeout_is_set_before_django_migrates(self):
        observed = {}

        def fake_handle(_self, *args, **options):
            observed["lock_timeout"] = _show_lock_timeout()

        with patch.object(DjangoMigrateCommand, "handle", fake_handle):
            call_command("migrate")

        assert observed["lock_timeout"] == "5s"

    def test_lock_timeout_value_is_configurable(self):
        observed = {}

        def fake_handle(_self, *args, **options):
            observed["lock_timeout"] = _show_lock_timeout()

        with (
            patch(
                "api.management.commands.migrate.MIGRATION_LOCK_TIMEOUT",
                "250ms",
            ),
            patch.object(DjangoMigrateCommand, "handle", fake_handle),
        ):
            call_command("migrate")

        assert observed["lock_timeout"] == "250ms"

    def test_lock_timeout_zero_disables_the_timeout(self):
        observed = {}

        def fake_handle(_self, *args, **options):
            observed["lock_timeout"] = _show_lock_timeout()

        with (
            patch("api.management.commands.migrate.MIGRATION_LOCK_TIMEOUT", "0"),
            patch.object(DjangoMigrateCommand, "handle", fake_handle),
        ):
            call_command("migrate")

        assert observed["lock_timeout"] == "0"

    def test_lock_timeout_applies_to_the_requested_database(self):
        with patch.object(DjangoMigrateCommand, "handle", Mock(return_value=None)):
            call_command("migrate", database=DEFAULT_DB_ALIAS)

        assert _show_lock_timeout() == "5s"


@pytest.mark.django_db(transaction=True)
class TestMigrateLockTimeoutFailureMode:
    """
    Exercises the real rollback semantics against Postgres: a migration blocked on
    a lock must fail fast and leave nothing half-applied.
    """

    table = "lock_timeout_probe"

    @pytest.fixture
    def blocked_table(self, settings):
        with connections[DEFAULT_DB_ALIAS].cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {self.table};")
            cursor.execute(f"CREATE TABLE {self.table} (id integer);")

        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        blocker = psycopg2.connect(
            dbname=db["NAME"],
            user=db["USER"],
            password=db["PASSWORD"],
            host=db["HOST"],
            port=db["PORT"],
        )
        with blocker.cursor() as cursor:
            cursor.execute(f"LOCK TABLE {self.table} IN ACCESS EXCLUSIVE MODE;")

        yield

        blocker.rollback()
        blocker.close()
        with connections[DEFAULT_DB_ALIAS].cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {self.table};")

    def _column_exists(self, column: str) -> bool:
        with connections[DEFAULT_DB_ALIAS].cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = %s AND column_name = %s;",
                [self.table, column],
            )
            return cursor.fetchone() is not None

    def _apply(self, atomic: bool):
        connection = connections[DEFAULT_DB_ALIAS]
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('lock_timeout', '250ms', FALSE);")

        migration = type(
            "ProbeMigration",
            (Migration,),
            {
                "atomic": atomic,
                "operations": [
                    RunSQL(f"CREATE TABLE {self.table}_first (id integer);"),
                    RunSQL(f"ALTER TABLE {self.table} ADD COLUMN blocked integer;"),
                ],
            },
        )("probe", "api")

        try:
            with connection.schema_editor(atomic=migration.atomic) as schema_editor:
                migration.apply(ProjectState(), schema_editor, collect_sql=False)
        finally:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('lock_timeout', '0', FALSE);")

    def _first_table_exists(self) -> bool:
        with connections[DEFAULT_DB_ALIAS].cursor() as cursor:
            cursor.execute("SELECT to_regclass(%s);", [f"{self.table}_first"])
            return cursor.fetchone()[0] is not None

    def _drop_first_table(self):
        with connections[DEFAULT_DB_ALIAS].cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {self.table}_first;")

    def test_atomic_migration_rolls_back_entirely(self, blocked_table):
        # Fixture holds the lock the migration blocks on; pytest injects it by
        # parameter name, so we reference it explicitly to keep static
        # analysers from flagging it as unused.
        del blocked_table
        try:
            with pytest.raises(OperationalError, match="lock timeout"):
                self._apply(atomic=True)

            assert not self._column_exists("blocked")
            # The whole migration is one transaction, so the operation that ran
            # before the blocked one is rolled back too: nothing half-applied.
            assert not self._first_table_exists()
        finally:
            self._drop_first_table()

    def test_non_atomic_migration_keeps_earlier_operations(self, blocked_table):
        del blocked_table
        try:
            with pytest.raises(OperationalError, match="lock timeout"):
                self._apply(atomic=False)

            assert not self._column_exists("blocked")
            # atomic = False has no surrounding transaction, so earlier operations
            # survive while the migration stays unrecorded. Re-running it replays
            # them. This is inherent to atomic = False, not to lock_timeout, but
            # lock_timeout makes it reachable more often.
            assert self._first_table_exists()
        finally:
            self._drop_first_table()
