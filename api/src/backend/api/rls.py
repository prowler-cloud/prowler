from typing import Any
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import DEFAULT_DB_ALIAS
from django.db import models
from django.db.backends.ddl_references import Statement, Table

from api.db_utils import DB_USER, POSTGRES_TENANT_VAR


class Tenant(models.Model):
    """
    The Tenant is the basic grouping in the system. It is used to separate data between customers.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100)

    class Meta:
        db_table = "tenants"

    class JSONAPIMeta:
        resource_name = "tenants"


class RowLevelSecurityConstraint(models.BaseConstraint):
    """
    Model constraint to enforce row-level security on a tenant based model, in addition to the least privileges.

    The constraint can be applied to a partitioned table by specifying the `partition_name` keyword argument.
    """

    rls_sql_query = """
        ALTER TABLE %(table_name)s ENABLE ROW LEVEL SECURITY;
        ALTER TABLE %(table_name)s FORCE ROW LEVEL SECURITY;
    """

    policy_sql_query = """
        CREATE POLICY %(db_user)s_%(table_name)s_{statement}
        ON %(table_name)s
        FOR {statement}
        TO %(db_user)s
        {clause} (
            CASE
                WHEN current_setting('%(tenant_setting)s', True) IS NULL THEN FALSE
                ELSE %(field_column)s = current_setting('%(tenant_setting)s')::uuid
            END
        );
    """

    grant_sql_query = """
        GRANT {statement} ON %(table_name)s TO %(db_user)s;
    """

    drop_sql_query = """
        ALTER TABLE %(table_name)s NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE %(table_name)s DISABLE ROW LEVEL SECURITY;
        REVOKE ALL ON TABLE %(table_name) TO %(db_user)s;
    """

    drop_policy_sql_query = """
        DROP POLICY IF EXISTS %(db_user)s_%(table_name)s_{statement} on %(table_name)s;
    """

    def __init__(
        self, field: str, name: str, statements: list | None = None, **kwargs
    ) -> None:
        super().__init__(name=name)
        self.target_field: str = field
        self.statements = statements or ["SELECT"]
        self.partition_name = None
        if "partition_name" in kwargs:
            self.partition_name = kwargs["partition_name"]

    def create_sql(self, model: Any, schema_editor: Any) -> Any:
        field_column = schema_editor.quote_name(self.target_field)

        policy_queries = ""
        grant_queries = ""
        for statement in self.statements:
            clause = f"{'WITH CHECK' if statement == 'INSERT' else 'USING'}"
            policy_queries = f"{policy_queries}{self.policy_sql_query.format(statement=statement, clause=clause)}"
            grant_queries = (
                f"{grant_queries}{self.grant_sql_query.format(statement=statement)}"
            )

        full_create_sql_query = (
            f"{self.rls_sql_query}" f"{policy_queries}" f"{grant_queries}"
        )

        table_name = model._meta.db_table
        if self.partition_name:
            table_name = f"{table_name}_{self.partition_name}"

        return Statement(
            full_create_sql_query,
            table_name=table_name,
            field_column=field_column,
            db_user=DB_USER,
            tenant_setting=POSTGRES_TENANT_VAR,
            partition_name=self.partition_name,
        )

    def remove_sql(self, model: Any, schema_editor: Any) -> Any:
        field_column = schema_editor.quote_name(self.target_field)
        full_drop_sql_query = (
            f"{self.drop_sql_query}"
            f"{''.join([self.drop_policy_sql_query.format(statement) for statement in self.statements])}"
        )
        table_name = model._meta.db_table
        if self.partition_name:
            table_name = f"{table_name}_{self.partition_name}"
        return Statement(
            full_drop_sql_query,
            table_name=Table(table_name, schema_editor.quote_name),
            field_column=field_column,
            db_user=DB_USER,
            partition_name=self.partition_name,
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RowLevelSecurityConstraint):
            return self.name == other.name and self.target_field == other.target_field
        return super().__eq__(other)

    def deconstruct(self) -> tuple[str, tuple, dict]:
        path, _, kwargs = super().deconstruct()
        return (path, (self.target_field,), kwargs)

    def validate(self, model, instance, exclude=None, using=DEFAULT_DB_ALIAS):  # noqa: F841
        if not hasattr(instance, "tenant_id"):
            raise ValidationError(f"{model.__name__} does not have a tenant_id field.")


class BaseSecurityConstraint(models.BaseConstraint):
    """Model constraint to grant the least privileges to the API database user."""

    grant_sql_query = """
        GRANT {statement} ON %(table_name)s TO %(db_user)s;
    """

    drop_sql_query = """
        REVOKE ALL ON TABLE %(table_name) TO %(db_user)s;
    """

    def __init__(self, name: str, statements: list | None = None) -> None:
        super().__init__(name=name)
        self.statements = statements or ["SELECT"]

    def create_sql(self, model: Any, schema_editor: Any) -> Any:
        grant_queries = ""
        for statement in self.statements:
            grant_queries = (
                f"{grant_queries}{self.grant_sql_query.format(statement=statement)}"
            )

        return Statement(
            grant_queries,
            table_name=model._meta.db_table,
            db_user=DB_USER,
        )

    def remove_sql(self, model: Any, schema_editor: Any) -> Any:
        return Statement(
            self.drop_sql_query,
            table_name=Table(model._meta.db_table, schema_editor.quote_name),
            db_user=DB_USER,
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BaseSecurityConstraint):
            return self.name == other.name
        return super().__eq__(other)

    def deconstruct(self) -> tuple[str, tuple, dict]:
        path, args, kwargs = super().deconstruct()
        return path, args, kwargs


class RowLevelSecurityProtectedModel(models.Model):
    tenant = models.ForeignKey("Tenant", on_delete=models.CASCADE)

    class Meta:
        abstract = True
