import re
import secrets
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from celery.utils.log import get_task_logger
from config.env import env
from django.conf import settings
from django.contrib.auth.models import BaseUserManager
from django.db import (
    DEFAULT_DB_ALIAS,
    OperationalError,
    connections,
    models,
    transaction,
)
from django_celery_beat.models import PeriodicTask
from psycopg2 import connect as psycopg2_connect
from psycopg2.extensions import AsIs, new_type, register_adapter, register_type
from rest_framework_json_api.serializers import ValidationError

from api.db_router import (
    READ_REPLICA_ALIAS,
    get_read_db_alias,
    reset_read_db_alias,
    set_read_db_alias,
)

logger = get_task_logger(__name__)

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
POSTGRES_USER_VAR = "api.user_id"

REPLICA_MAX_ATTEMPTS = env.int("POSTGRES_REPLICA_MAX_ATTEMPTS", default=3)
REPLICA_RETRY_BASE_DELAY = env.float("POSTGRES_REPLICA_RETRY_BASE_DELAY", default=0.5)

SET_CONFIG_QUERY = "SELECT set_config(%s, %s::text, TRUE);"


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
            port=admin_db["PORT"],
        )
        yield psycopg2_connection
    finally:
        if psycopg2_connection is not None:
            psycopg2_connection.close()


@contextmanager
def rls_transaction(
    value: str,
    parameter: str = POSTGRES_TENANT_VAR,
    using: str | None = None,
):
    """
    Creates a new database transaction setting the given configuration value for Postgres RLS. It validates the
    if the value is a valid UUID.

    Args:
        value (str): Database configuration parameter value.
        parameter (str): Database configuration parameter name, by default is 'api.tenant_id'.
        using (str | None): Optional database alias to run the transaction against. Defaults to the
            active read alias (if any) or Django's default connection.
    """
    requested_alias = using or get_read_db_alias()
    db_alias = requested_alias or DEFAULT_DB_ALIAS
    if db_alias not in connections:
        db_alias = DEFAULT_DB_ALIAS

    alias = db_alias
    is_replica = READ_REPLICA_ALIAS and alias == READ_REPLICA_ALIAS
    max_attempts = REPLICA_MAX_ATTEMPTS if is_replica else 1

    for attempt in range(1, max_attempts + 1):
        router_token = None

        # On final attempt, fallback to primary
        if attempt == max_attempts and is_replica:
            logger.warning(
                f"RLS transaction failed after {attempt - 1} attempts on replica, "
                f"falling back to primary DB"
            )
            alias = DEFAULT_DB_ALIAS

        conn = connections[alias]
        try:
            if alias != DEFAULT_DB_ALIAS:
                router_token = set_read_db_alias(alias)

            with transaction.atomic(using=alias):
                with conn.cursor() as cursor:
                    try:
                        # just in case the value is a UUID object
                        uuid.UUID(str(value))
                    except ValueError:
                        raise ValidationError("Must be a valid UUID")
                    cursor.execute(SET_CONFIG_QUERY, [parameter, value])
                    yield cursor
            return
        except OperationalError as e:
            # If on primary or max attempts reached, raise
            if not is_replica or attempt == max_attempts:
                raise

            # Retry with exponential backoff
            delay = REPLICA_RETRY_BASE_DELAY * (2 ** (attempt - 1))
            logger.info(
                f"RLS transaction failed on replica (attempt {attempt}/{max_attempts}), "
                f"retrying in {delay}s. Error: {e}"
            )
            time.sleep(delay)
        finally:
            if router_token is not None:
                reset_read_db_alias(router_token)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def get_by_natural_key(self, email):
        return self.get(email__iexact=email)


def enum_to_choices(enum_class):
    """
    This function converts a Python Enum to a list of tuples, where the first element is the value and the second element is the name.

    It's for use with Django's `choices` attribute, which expects a list of tuples.
    """
    return [(item.value, item.name.replace("_", " ").title()) for item in enum_class]


def one_week_from_now():
    """
    Return a datetime object with a date one week from now.
    """
    return datetime.now(timezone.utc) + timedelta(days=7)


def generate_random_token(length: int = 14, symbols: str | None = None) -> str:
    """
    Generate a random token with the specified length.
    """
    _symbols = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(secrets.choice(symbols or _symbols) for _ in range(length))


def batch_delete(tenant_id, queryset, batch_size=settings.DJANGO_DELETION_BATCH_SIZE):
    """
    Deletes objects in batches and returns the total number of deletions and a summary.

    Args:
        tenant_id (str): Tenant ID the queryset belongs to.
        queryset (QuerySet): The queryset of objects to delete.
        batch_size (int): The number of objects to delete in each batch.

    Returns:
        tuple: (total_deleted, deletion_summary)
    """
    total_deleted = 0
    deletion_summary = {}

    while True:
        with rls_transaction(tenant_id, POSTGRES_TENANT_VAR):
            # Get a batch of IDs to delete
            batch_ids = set(
                queryset.values_list("id", flat=True).order_by("id")[:batch_size]
            )
            if not batch_ids:
                # No more objects to delete
                break

            deleted_count, deleted_info = queryset.filter(id__in=batch_ids).delete()

        total_deleted += deleted_count
        for model_label, count in deleted_info.items():
            deletion_summary[model_label] = deletion_summary.get(model_label, 0) + count

    return total_deleted, deletion_summary


def delete_related_daily_task(provider_id: str):
    """
    Deletes the periodic task associated with a specific provider.

    Args:
        provider_id (str): The unique identifier for the provider
                           whose related periodic task should be deleted.
    """
    task_name = f"scan-perform-scheduled-{provider_id}"
    PeriodicTask.objects.filter(name=task_name).delete()


def create_objects_in_batches(
    tenant_id: str, model, objects: list, batch_size: int = 500
):
    """
    Bulk-create model instances in repeated, per-tenant RLS transactions.

    All chunks execute in their own transaction, so no single transaction
    grows too large.

    Args:
        tenant_id (str): UUID string of the tenant under which to set RLS.
        model: Django model class whose `.objects.bulk_create()` will be called.
        objects (list): List of model instances (unsaved) to bulk-create.
        batch_size (int): Maximum number of objects per bulk_create call.
    """
    total = len(objects)
    for i in range(0, total, batch_size):
        chunk = objects[i : i + batch_size]
        with rls_transaction(value=tenant_id, parameter=POSTGRES_TENANT_VAR):
            model.objects.bulk_create(chunk, batch_size)


def update_objects_in_batches(
    tenant_id: str, model, objects: list, fields: list, batch_size: int = 500
):
    """
    Bulk-update model instances in repeated, per-tenant RLS transactions.

    All chunks execute in their own transaction, so no single transaction
    grows too large.

    Args:
        tenant_id (str): UUID string of the tenant under which to set RLS.
        model: Django model class whose `.objects.bulk_update()` will be called.
        objects (list): List of model instances (saved) to bulk-update.
        fields (list): List of field names to update.
        batch_size (int): Maximum number of objects per bulk_update call.
    """
    total = len(objects)
    for start in range(0, total, batch_size):
        chunk = objects[start : start + batch_size]
        with rls_transaction(value=tenant_id, parameter=POSTGRES_TENANT_VAR):
            model.objects.bulk_update(chunk, fields, batch_size)


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


def _should_create_index_on_partition(
    partition_name: str, all_partitions: bool = False
) -> bool:
    """
    Determine if we should create an index on this partition.

    Args:
        partition_name: The name of the partition (e.g., "findings_2025_aug", "findings_default")
        all_partitions: If True, create on all partitions. If False, only current/future partitions.

    Returns:
        bool: True if index should be created on this partition, False otherwise.
    """
    if all_partitions:
        return True

    # Extract date from partition name if it follows the pattern
    # Partition names look like: findings_2025_aug, findings_2025_jul, etc.
    date_pattern = r"(\d{4})_([a-z]{3})$"
    match = re.search(date_pattern, partition_name)

    if not match:
        # If we can't parse the date, include it to be safe (e.g., default partition)
        return True

    try:
        year_str, month_abbr = match.groups()
        year = int(year_str)

        # Map month abbreviations to numbers
        month_map = {
            "jan": 1,
            "feb": 2,
            "mar": 3,
            "apr": 4,
            "may": 5,
            "jun": 6,
            "jul": 7,
            "aug": 8,
            "sep": 9,
            "oct": 10,
            "nov": 11,
            "dec": 12,
        }

        month = month_map.get(month_abbr.lower())
        if month is None:
            # Unknown month abbreviation, include it to be safe
            return True

        partition_date = datetime(year, month, 1, tzinfo=timezone.utc)

        # Get current month start
        now = datetime.now(timezone.utc)
        current_month_start = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        # Include current month and future partitions
        return partition_date >= current_month_start

    except (ValueError, TypeError):
        # If date parsing fails, include it to be safe
        return True


def create_index_on_partitions(
    apps,  # noqa: F841
    schema_editor,
    parent_table: str,
    index_name: str,
    columns: str,
    method: str = "BTREE",
    where: str = "",
    all_partitions: bool = True,
):
    """
    Create an index on existing partitions of `parent_table`.

    Args:
        parent_table: The name of the root table (e.g. "findings").
        index_name: A short name for the index (will be prefixed per-partition).
        columns: The parenthesized column list, e.g. "tenant_id, scan_id, status".
        method: The index method—BTREE, GIN, etc. Defaults to BTREE.
        where: Optional WHERE clause (without the leading "WHERE"), e.g. "status = 'FAIL'".
        all_partitions: Whether to create indexes on all partitions or just current/future ones.
                       Defaults to False (current/future only) to avoid maintenance overhead
                       on old partitions where the index may not be needed.

    Examples:
        # Create index only on current and future partitions (recommended for new indexes)
        create_index_on_partitions(
            apps, schema_editor,
            parent_table="findings",
            index_name="new_performance_idx",
            columns="tenant_id, status, severity",
            all_partitions=False  # Default behavior
        )

        # Create index on all partitions (use when migrating existing critical indexes)
        create_index_on_partitions(
            apps, schema_editor,
            parent_table="findings",
            index_name="critical_existing_idx",
            columns="tenant_id, scan_id",
            all_partitions=True
        )
    """
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT inhrelid::regclass::text
            FROM pg_inherits
            WHERE inhparent = %s::regclass
            """,
            [parent_table],
        )
        partitions = [row[0] for row in cursor.fetchall()]

    where_sql = f" WHERE {where}" if where else ""
    conn = schema_editor.connection
    for partition in partitions:
        if _should_create_index_on_partition(partition, all_partitions):
            idx_name = f"{partition.replace('.', '_')}_{index_name}"
            sql = (
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {idx_name} "
                f"ON {partition} USING {method} ({columns})"
                f"{where_sql};"
            )
            old_autocommit = conn.connection.autocommit
            conn.connection.autocommit = True
            try:
                schema_editor.execute(sql)
            finally:
                conn.connection.autocommit = old_autocommit


def drop_index_on_partitions(
    apps,  # noqa: F841
    schema_editor,
    parent_table: str,
    index_name: str,
):
    """
    Drop the per-partition indexes that were created by create_index_on_partitions.

    Args:
        parent_table: The name of the root table (e.g. "findings").
        index_name: The same short name used when creating them.
    """
    conn = schema_editor.connection
    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT inhrelid::regclass::text
            FROM pg_inherits
            WHERE inhparent = %s::regclass
            """,
            [parent_table],
        )
        partitions = [row[0] for row in cursor.fetchall()]

    for partition in partitions:
        idx_name = f"{partition.replace('.', '_')}_{index_name}"
        sql = f"DROP INDEX CONCURRENTLY IF EXISTS {idx_name};"
        old_autocommit = conn.connection.autocommit
        conn.connection.autocommit = True
        try:
            schema_editor.execute(sql)
        finally:
            conn.connection.autocommit = old_autocommit


def generate_api_key_prefix():
    """Generate a random 8-character prefix for API keys (e.g., 'pk_abc123de')."""
    random_chars = generate_random_token(length=8)
    return f"pk_{random_chars}"


# Postgres enum definition for member role


class MemberRoleEnum(EnumType):
    enum_type_name = "member_role"


class MemberRoleEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("member_role", *args, **kwargs)


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


# Postgres enum definition for Finding.Delta


class FindingDeltaEnum(EnumType):
    enum_type_name = "finding_delta"


class FindingDeltaEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("finding_delta", *args, **kwargs)


# Postgres enum definition for Severity


class SeverityEnum(EnumType):
    enum_type_name = "severity"


class SeverityEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("severity", *args, **kwargs)


# Postgres enum definition for Status


class StatusEnum(EnumType):
    enum_type_name = "status"


class StatusEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("status", *args, **kwargs)


# Postgres enum definition for Provider secrets type


class ProviderSecretTypeEnum(EnumType):
    enum_type_name = "provider_secret_type"


class ProviderSecretTypeEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("provider_secret_type", *args, **kwargs)


# Postgres enum definition for Provider secrets type


class InvitationStateEnum(EnumType):
    enum_type_name = "invitation_state"


class InvitationStateEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("invitation_state", *args, **kwargs)


# Postgres enum definition for Integration type


class IntegrationTypeEnum(EnumType):
    enum_type_name = "integration_type"


class IntegrationTypeEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("integration_type", *args, **kwargs)


# Postgres enum definition for Processor type


class ProcessorTypeEnum(EnumType):
    enum_type_name = "processor_type"


class ProcessorTypeEnumField(PostgresEnumField):
    def __init__(self, *args, **kwargs):
        super().__init__("processor_type", *args, **kwargs)
