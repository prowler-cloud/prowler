from contextlib import contextmanager

from django.conf import settings
from django.db import models
from psycopg2 import connect as psycopg2_connect
from psycopg2.extensions import new_type, register_type, register_adapter, AsIs

DB_USER = settings.DATABASES["default"]["USER"] if not settings.TESTING else "test"
DB_PASSWORD = (
    settings.DATABASES["default"]["PASSWORD"] if not settings.TESTING else "test"
)
DB_PROWLER_USER = (
    settings.DATABASES["prowler_user"]["USER"] if not settings.TESTING else "test"
)
DB_PROWLER_PASSWORD = (
    settings.DATABASES["prowler_user"]["PASSWORD"] if not settings.TESTING else "test"
)
TASK_RUNNER_DB_TABLE = "django_celery_results_taskresult"
POSTGRES_TENANT_VAR = "api.tenant_id"


@contextmanager
def psycopg_connection(database_alias: str):
    psycopg2_connection = None
    try:
        admin_db = settings.DATABASES[database_alias]

        psycopg2_connection = psycopg2_connect(
            dbname=admin_db["NAME"],
            user=admin_db["USER"],
            password=admin_db["PASSWORD"],
            host=admin_db["HOST"],
        )
        yield psycopg2_connection
    finally:
        if psycopg2_connection is not None:
            psycopg2_connection.close()


# Postgres Enums


class PostgresEnumMigration:
    def __init__(self, enum_name: str, enum_values: tuple):
        self.enum_name = enum_name
        self.enum_values = enum_values

    def create_enum_type(self, apps, schema_editor):  # noqa: F841
        string_enum_values = ", ".join([f"'{value}'" for value in self.enum_values])
        with schema_editor.connection.cursor() as cursor:
            cursor.execute(
                f"CREATE TYPE {self.enum_name} AS ENUM ({string_enum_values});"
            )

    def drop_enum_type(self, apps, schema_editor):  # noqa: F841
        with schema_editor.connection.cursor() as cursor:
            cursor.execute(f"DROP TYPE {self.enum_name};")


class PostgresEnumField(models.Field):
    def __init__(self, enum_type_name, *args, **kwargs):
        self.enum_type_name = enum_type_name
        super().__init__(*args, **kwargs)

    def db_type(self, connection):
        return self.enum_type_name

    def from_db_value(self, value, expression, connection):  # noqa: F841
        return value

    def to_python(self, value):
        if isinstance(value, EnumType):
            return value.value
        return value

    def get_prep_value(self, value):
        if isinstance(value, EnumType):
            return value.value
        return value


class EnumType:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


def enum_adapter(enum_obj):
    return AsIs(f"'{enum_obj.value}'::{enum_obj.__class__.enum_type_name}")


def get_enum_oid(connection, enum_type_name: str):
    with connection.cursor() as cursor:
        cursor.execute("SELECT oid FROM pg_type WHERE typname = %s;", (enum_type_name,))
        result = cursor.fetchone()
    if result is None:
        raise ValueError(f"Enum type '{enum_type_name}' not found")
    return result[0]


def register_enum(apps, schema_editor, enum_class):  # noqa: F841
    with psycopg_connection(schema_editor.connection.alias) as connection:
        enum_oid = get_enum_oid(connection, enum_class.enum_type_name)
        enum_instance = new_type(
            (enum_oid,),
            enum_class.enum_type_name,
            lambda value, cur: value,  # noqa: F841
        )
        register_type(enum_instance, connection)
        register_adapter(enum_class, enum_adapter)


# Postgres enum definition for Provider.provider


class ProviderEnum(EnumType):
    enum_type_name = "provider"


class ProviderEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("provider", *args, **kwargs)


# Postgres enum definition for Scan.type


class ScanTriggerEnum(EnumType):
    enum_type_name = "scan_trigger"


class ScanTriggerEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("scan_trigger", *args, **kwargs)


# Postgres enum definition for state


class StateEnum(EnumType):
    enum_type_name = "state"


class StateEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("state", *args, **kwargs)
