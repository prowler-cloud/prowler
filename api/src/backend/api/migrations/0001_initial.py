import uuid
from functools import partial

import django.contrib.auth.models
import django.contrib.postgres.indexes
import django.contrib.postgres.search
import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models
from psqlextra.backend.migrations.operations.add_default_partition import (
    PostgresAddDefaultPartition,
)
from psqlextra.backend.migrations.operations.create_partitioned_model import (
    PostgresCreatePartitionedModel,
)
from psqlextra.manager.manager import PostgresManager
from psqlextra.models.partitioned import PostgresPartitionedModel
from psqlextra.types import PostgresPartitioningMethod
from uuid6 import uuid7

import api.rls
from api.db_utils import (
    DB_PROWLER_PASSWORD,
    DB_PROWLER_USER,
    POSTGRES_TENANT_VAR,
    POSTGRES_USER_VAR,
    TASK_RUNNER_DB_TABLE,
    InvitationStateEnum,
    InvitationStateEnumField,
    MemberRoleEnum,
    MemberRoleEnumField,
    PostgresEnumMigration,
    ProviderEnum,
    ProviderEnumField,
    ProviderSecretTypeEnum,
    ProviderSecretTypeEnumField,
    ScanTriggerEnum,
    ScanTriggerEnumField,
    StateEnum,
    StateEnumField,
    register_enum,
)
from api.models import (
    Finding,
    Invitation,
    Membership,
    Provider,
    ProviderSecret,
    Scan,
    SeverityChoices,
    StateChoices,
    StatusChoices,
)

DB_NAME = settings.DATABASES["default"]["NAME"]

MemberRoleEnumMigration = PostgresEnumMigration(
    enum_name="member_role",
    enum_values=tuple(role[0] for role in Membership.RoleChoices.choices),
)

ProviderEnumMigration = PostgresEnumMigration(
    enum_name="provider",
    enum_values=tuple(provider[0] for provider in Provider.ProviderChoices.choices),
)

ScanTriggerEnumMigration = PostgresEnumMigration(
    enum_name="scan_trigger",
    enum_values=tuple(scan_trigger[0] for scan_trigger in Scan.TriggerChoices.choices),
)

StateEnumMigration = PostgresEnumMigration(
    enum_name="state",
    enum_values=tuple(state[0] for state in StateChoices.choices),
)

FindingDeltaEnumMigration = PostgresEnumMigration(
    enum_name="finding_delta",
    enum_values=tuple(
        finding_delta[0] for finding_delta in Finding.DeltaChoices.choices
    ),
)

StatusEnumMigration = PostgresEnumMigration(
    enum_name="status",
    enum_values=tuple(status[0] for status in StatusChoices.choices),
)

SeverityEnumMigration = PostgresEnumMigration(
    enum_name="severity",
    enum_values=tuple(severity[0] for severity in SeverityChoices),
)

ProviderSecretTypeEnumMigration = PostgresEnumMigration(
    enum_name="provider_secret_type",
    enum_values=tuple(
        secret_type[0] for secret_type in ProviderSecret.TypeChoices.choices
    ),
)

InvitationStateEnumMigration = PostgresEnumMigration(
    enum_name="invitation_state",
    enum_values=tuple(state[0] for state in Invitation.State.choices),
)


class Migration(migrations.Migration):
    initial = True
    # Required for our kind of `RunPython` operations
    atomic = False

    dependencies = [
        ("django_celery_results", "0011_taskresult_periodic_task_name"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunSQL(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT
                    FROM   pg_catalog.pg_roles
                    WHERE  rolname = '{DB_PROWLER_USER}') THEN
                    CREATE ROLE {DB_PROWLER_USER} LOGIN PASSWORD '{DB_PROWLER_PASSWORD}';
                END IF;
            END
            $$;
            """
        ),
        migrations.RunSQL(
            # Required permissions for API user related tables
            f"""
            GRANT CONNECT ON DATABASE "{DB_NAME}" TO {DB_PROWLER_USER};
            GRANT SELECT ON django_migrations TO {DB_PROWLER_USER};
            """
        ),
        migrations.CreateModel(
            name="User",
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
                (
                    "name",
                    models.CharField(
                        max_length=150,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        error_messages={
                            "unique": "Please check the email address and try again."
                        },
                        help_text="Case insensitive",
                        max_length=254,
                        unique=True,
                    ),
                ),
                ("company_name", models.CharField(max_length=150, blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("date_joined", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "users",
            },
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=api.rls.BaseSecurityConstraint(
                name="statements_on_user",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        # Create and register State type
        migrations.RunPython(
            StateEnumMigration.create_enum_type,
            reverse_code=StateEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=StateEnum)),
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
                "db_table": "tenants",
            },
        ),
        migrations.RunSQL(
            # Needed for now since we don't have users yet
            f"""
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenants TO {DB_PROWLER_USER};
            """
        ),
        # Create and register MemberRoleEnum type
        migrations.RunPython(
            MemberRoleEnumMigration.create_enum_type,
            reverse_code=MemberRoleEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=MemberRoleEnum)),
        migrations.CreateModel(
            name="Membership",
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
                (
                    "role",
                    MemberRoleEnumField(
                        choices=[("owner", "Owner"), ("member", "Member")],
                        default="member",
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(auto_now_add=True, editable=False),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="memberships",
                        related_query_name="membership",
                        to="api.tenant",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="memberships",
                        related_query_name="membership",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "memberships",
            },
        ),
        migrations.AddConstraint(
            model_name="membership",
            constraint=api.rls.BaseSecurityConstraint(
                name="statements_on_membership",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="membership",
            constraint=models.UniqueConstraint(
                fields=("user", "tenant"),
                name="unique_resources_by_membership",
            ),
        ),
        # Enable tenants RLS based on memberships
        migrations.RunSQL(
            f"""
        ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

        -- Policy for SELECT
        CREATE POLICY "{DB_PROWLER_USER}_tenants_select"
        ON tenants
        FOR SELECT
        TO {DB_PROWLER_USER}
        USING (
            CASE
                WHEN (current_setting('{POSTGRES_USER_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_USER_VAR}', true) <> '') THEN
                    EXISTS (
                        SELECT 1
                        FROM memberships
                        WHERE
                            memberships.tenant_id = tenants.id
                            AND memberships.user_id = current_setting('{POSTGRES_USER_VAR}', true)::uuid
                    )
                WHEN (current_setting('{POSTGRES_TENANT_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_TENANT_VAR}', true) <> '') THEN
                    tenants.id = current_setting('{POSTGRES_TENANT_VAR}', true)::uuid
                ELSE
                    FALSE
            END
        );

        -- Policy for UPDATE
        CREATE POLICY "{DB_PROWLER_USER}_tenants_update"
        ON tenants
        FOR UPDATE
        TO {DB_PROWLER_USER}
        USING (
            CASE
                WHEN (current_setting('{POSTGRES_USER_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_USER_VAR}', true) <> '') THEN
                    EXISTS (
                        SELECT 1
                        FROM memberships
                        WHERE
                            memberships.tenant_id = tenants.id
                            AND memberships.user_id = current_setting('{POSTGRES_USER_VAR}', true)::uuid
                    )
                WHEN (current_setting('{POSTGRES_TENANT_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_TENANT_VAR}', true) <> '') THEN
                    tenants.id = current_setting('{POSTGRES_TENANT_VAR}', true)::uuid
                ELSE
                    FALSE
            END
        );

        -- Policy for DELETE
        CREATE POLICY "{DB_PROWLER_USER}_tenants_delete"
        ON tenants
        FOR DELETE
        TO {DB_PROWLER_USER}
        USING (
            CASE
                WHEN (current_setting('{POSTGRES_USER_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_USER_VAR}', true) <> '') THEN
                    EXISTS (
                        SELECT 1
                        FROM memberships
                        WHERE
                            memberships.tenant_id = tenants.id
                            AND memberships.user_id = current_setting('{POSTGRES_USER_VAR}', true)::uuid
                    )
                WHEN (current_setting('{POSTGRES_TENANT_VAR}', true) IS NOT NULL AND current_setting('{POSTGRES_TENANT_VAR}', true) <> '') THEN
                    tenants.id = current_setting('{POSTGRES_TENANT_VAR}', true)::uuid
                ELSE
                    FALSE
            END
        );

        -- Policy for INSERT
        CREATE POLICY "{DB_PROWLER_USER}_tenants_insert"
        ON tenants
        FOR INSERT
        TO {DB_PROWLER_USER}
        WITH CHECK (true);
                """
        ),
        # Create and register ProviderEnum type
        migrations.RunPython(
            ProviderEnumMigration.create_enum_type,
            reverse_code=ProviderEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=ProviderEnum)),
        migrations.CreateModel(
            name="Provider",
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
                ("is_deleted", models.BooleanField(default=False)),
                (
                    "provider",
                    ProviderEnumField(
                        choices=[
                            ("aws", "AWS"),
                            ("azure", "Azure"),
                            ("gcp", "GCP"),
                            ("kubernetes", "Kubernetes"),
                        ],
                        default="aws",
                    ),
                ),
                (
                    "uid",
                    models.CharField(
                        max_length=63,
                        validators=[django.core.validators.MinLengthValidator(3)],
                        verbose_name="Unique identifier for the provider, set by the provider",
                    ),
                ),
                (
                    "alias",
                    models.CharField(
                        blank=True,
                        null=True,
                        max_length=100,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                ("connected", models.BooleanField(blank=True, null=True)),
                (
                    "connection_last_checked_at",
                    models.DateTimeField(blank=True, null=True),
                ),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("scanner_args", models.JSONField(blank=True, default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "abstract": False,
                "db_table": "providers",
            },
        ),
        migrations.AddConstraint(
            model_name="provider",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_provider",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="provider",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider", "uid"),
                name="unique_provider_uids",
            ),
        ),
        migrations.CreateModel(
            name="ProviderGroup",
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
                ("name", models.CharField(max_length=255)),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "provider_groups",
            },
        ),
        migrations.CreateModel(
            name="ProviderGroupMembership",
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
            ],
            options={
                "db_table": "provider_group_memberships",
            },
        ),
        migrations.AddField(
            model_name="providergroup",
            name="tenant",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to="api.tenant",
            ),
        ),
        migrations.AddField(
            model_name="providergroup",
            name="providers",
            field=models.ManyToManyField(
                related_name="provider_groups",
                through="api.ProviderGroupMembership",
                to="api.provider",
            ),
        ),
        migrations.AddField(
            model_name="providergroupmembership",
            name="tenant",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
            ),
        ),
        migrations.AddField(
            model_name="providergroupmembership",
            name="provider",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="api.provider"
            ),
        ),
        migrations.AddField(
            model_name="providergroupmembership",
            name="provider_group",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="api.providergroup"
            ),
        ),
        migrations.AddConstraint(
            model_name="providergroup",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_providergroup",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="providergroup",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"), name="unique_group_name_per_tenant"
            ),
        ),
        migrations.AddConstraint(
            model_name="providergroupmembership",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_providergroupmembership",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="providergroupmembership",
            constraint=models.UniqueConstraint(
                fields=("provider_id", "provider_group"),
                name="unique_provider_group_membership",
            ),
        ),
        migrations.CreateModel(
            name="Task",
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
                (
                    "task_runner_task",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="task",
                        related_query_name="task",
                        to="django_celery_results.taskresult",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "tasks",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="task",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_task",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="task",
            index=models.Index(
                fields=["id", "task_runner_task"],
                name="tasks_id_trt_id_idx",
            ),
        ),
        migrations.RunSQL(
            f"""
        ALTER TABLE {TASK_RUNNER_DB_TABLE} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "{DB_PROWLER_USER}_{TASK_RUNNER_DB_TABLE}_select"
        ON {TASK_RUNNER_DB_TABLE}
        FOR SELECT
        TO {DB_PROWLER_USER}
        USING (
            task_id::uuid in (SELECT id FROM tasks WHERE tenant_id = (NULLIF(current_setting('{POSTGRES_TENANT_VAR}', true), ''))::uuid)
        );
        GRANT SELECT ON TABLE {TASK_RUNNER_DB_TABLE} TO {DB_PROWLER_USER};
        """
        ),
        # Create and register ScanTriggerEnum type
        migrations.RunPython(
            ScanTriggerEnumMigration.create_enum_type,
            reverse_code=ScanTriggerEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=ScanTriggerEnum)),
        migrations.CreateModel(
            name="Scan",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        blank=True,
                        max_length=100,
                        null=True,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                (
                    "trigger",
                    ScanTriggerEnumField(
                        choices=[("scheduled", "Scheduled"), ("manual", "Manual")]
                    ),
                ),
                (
                    "state",
                    StateEnumField(
                        choices=[
                            ("available", "Available"),
                            ("scheduled", "Scheduled"),
                            ("executing", "Executing"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="available",
                    ),
                ),
                ("unique_resource_count", models.IntegerField(default=0)),
                ("progress", models.IntegerField(default=0)),
                ("scanner_args", models.JSONField(default=dict)),
                ("duration", models.IntegerField(blank=True, null=True)),
                (
                    "scheduled_at",
                    models.DateTimeField(null=True, blank=True),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("completed_at", models.DateTimeField(null=True, blank=True)),
                ("next_scan_at", models.DateTimeField(null=True, blank=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scans",
                        related_query_name="scan",
                        to="api.provider",
                    ),
                ),
                (
                    "task",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scans",
                        related_query_name="scan",
                        to="api.task",
                        null=True,
                        blank=True,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "scans",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="scan",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scan",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="scan",
            index=models.Index(
                fields=["provider", "state", "trigger", "scheduled_at"],
                name="scans_prov_state_trig_sche_idx",
            ),
        ),
        # Resources
        migrations.RunSQL(
            sql="""
          CREATE EXTENSION IF NOT EXISTS pg_trgm;
          """,
            reverse_sql="""
          DROP EXTENSION IF EXISTS pg_trgm;
          """,
        ),
        migrations.CreateModel(
            name="Resource",
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
                (
                    "uid",
                    models.TextField(
                        verbose_name="Unique identifier for the resource, set by the provider"
                    ),
                ),
                (
                    "name",
                    models.TextField(
                        verbose_name="Name of the resource, as set in the provider"
                    ),
                ),
                (
                    "region",
                    models.TextField(
                        verbose_name="Location of the resource, as set by the provider"
                    ),
                ),
                (
                    "service",
                    models.TextField(
                        verbose_name="Service of the resource, as set by the provider"
                    ),
                ),
                (
                    "type",
                    models.TextField(
                        verbose_name="Type of the resource, as set by the provider"
                    ),
                ),
                (
                    "text_search",
                    models.GeneratedField(
                        db_persist=True,
                        expression=django.contrib.postgres.search.CombinedSearchVector(
                            django.contrib.postgres.search.CombinedSearchVector(
                                django.contrib.postgres.search.CombinedSearchVector(
                                    django.contrib.postgres.search.SearchVector(
                                        "uid", config="simple", weight="A"
                                    ),
                                    "||",
                                    django.contrib.postgres.search.SearchVector(
                                        "name", config="simple", weight="B"
                                    ),
                                    django.contrib.postgres.search.SearchConfig(
                                        "simple"
                                    ),
                                ),
                                "||",
                                django.contrib.postgres.search.SearchVector(
                                    "region", config="simple", weight="C"
                                ),
                                django.contrib.postgres.search.SearchConfig("simple"),
                            ),
                            "||",
                            django.contrib.postgres.search.SearchVector(
                                "service", "type", config="simple", weight="D"
                            ),
                            django.contrib.postgres.search.SearchConfig("simple"),
                        ),
                        null=True,
                        output_field=django.contrib.postgres.search.SearchVectorField(),
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="resources",
                        related_query_name="resource",
                        to="api.provider",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "resources",
                "abstract": False,
            },
        ),
        migrations.AddIndex(
            model_name="resource",
            index=models.Index(
                fields=["uid", "region", "service", "name"],
                name="resource_uid_reg_serv_name_idx",
            ),
        ),
        migrations.CreateModel(
            name="ResourceTag",
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
                ("key", models.TextField()),
                ("value", models.TextField()),
                (
                    "text_search",
                    models.GeneratedField(
                        db_persist=True,
                        expression=django.contrib.postgres.search.CombinedSearchVector(
                            django.contrib.postgres.search.SearchVector(
                                "key", config="simple", weight="A"
                            ),
                            "||",
                            django.contrib.postgres.search.SearchVector(
                                "value", config="simple", weight="B"
                            ),
                            django.contrib.postgres.search.SearchConfig("simple"),
                        ),
                        null=True,
                        output_field=django.contrib.postgres.search.SearchVectorField(),
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "resource_tags",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="ResourceTagMapping",
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
                (
                    "resource",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.resource",
                    ),
                ),
                (
                    "tag",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.resourcetag",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "resource_tag_mappings",
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="resource",
            name="tags",
            field=models.ManyToManyField(
                through="api.ResourceTagMapping",
                to="api.resourcetag",
                verbose_name="Tags associated with the resource, by provider",
            ),
        ),
        migrations.AddIndex(
            model_name="resourcetag",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["text_search"], name="gin_resource_tags_search_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="resource",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["text_search"], name="gin_resources_search_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcetag",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "key", "value"),
                name="unique_resource_tags_by_tenant_key_value",
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcetag",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_resourcetag",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcetagmapping",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "resource_id", "tag_id"),
                name="unique_resource_tag_mappings_by_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcetagmapping",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_resourcetagmapping",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="resource",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider_id", "uid"),
                name="unique_resources_by_provider",
            ),
        ),
        migrations.AddConstraint(
            model_name="resource",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_resource",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        # Create and register ScanTypeEnum type
        migrations.RunPython(
            FindingDeltaEnumMigration.create_enum_type,
            reverse_code=FindingDeltaEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(
            StatusEnumMigration.create_enum_type,
            reverse_code=StatusEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(
            SeverityEnumMigration.create_enum_type,
            reverse_code=SeverityEnumMigration.drop_enum_type,
        ),
        PostgresCreatePartitionedModel(
            name="Finding",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("uid", models.CharField(max_length=300)),
                (
                    "delta",
                    api.db_utils.FindingDeltaEnumField(
                        choices=[("new", "New"), ("changed", "Changed")],
                        blank=True,
                        null=True,
                    ),
                ),
                (
                    "status",
                    api.db_utils.StatusEnumField(
                        choices=[
                            ("FAIL", "Fail"),
                            ("PASS", "Pass"),
                            ("MANUAL", "Manual"),
                            ("MUTED", "Muted"),
                        ]
                    ),
                ),
                ("status_extended", models.TextField(blank=True, null=True)),
                (
                    "severity",
                    api.db_utils.SeverityEnumField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                            ("informational", "Informational"),
                        ]
                    ),
                ),
                (
                    "impact",
                    api.db_utils.SeverityEnumField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                            ("informational", "Informational"),
                        ]
                    ),
                ),
                ("impact_extended", models.TextField(blank=True, null=True)),
                ("raw_result", models.JSONField(default=dict)),
                ("check_id", models.CharField(max_length=100, null=False)),
                ("check_metadata", models.JSONField(default=dict, null=False)),
                ("tags", models.JSONField(default=dict, blank=True, null=True)),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="findings",
                        to="api.scan",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "findings",
                "base_manager_name": "objects",
            },
            partitioning_options={
                "method": PostgresPartitioningMethod["RANGE"],
                "key": ["id"],
            },
            bases=(PostgresPartitionedModel,),
            managers=[
                ("objects", api.models.ActiveProviderPartitionedManager()),
            ],
        ),
        migrations.RunSQL(
            sql="""
              ALTER TABLE findings
                ADD COLUMN text_search tsvector
                GENERATED ALWAYS AS (
                  setweight(to_tsvector('english', coalesce(impact_extended, '')), 'A') ||
                  setweight(to_tsvector('english', coalesce(status_extended, '')), 'B') ||
                  setweight(jsonb_to_tsvector('simple', check_metadata, '["string", "numeric"]'), 'D') ||
                  setweight(jsonb_to_tsvector('simple', tags, '["string", "numeric"]'), 'D')
                ) STORED;
            """,
            reverse_sql="""
              ALTER TABLE findings
                DROP COLUMN text_search;
              """,
            state_operations=[
                migrations.AddField(
                    model_name="finding",
                    name="text_search",
                    field=models.GeneratedField(
                        db_persist=True,
                        expression=django.contrib.postgres.search.SearchVector(
                            "impact_extended",
                            "status_extended",
                            config="simple",
                            weight="A",
                        ),
                        null=True,
                        output_field=django.contrib.postgres.search.SearchVectorField(),
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["uid"],
                name="findings_uid_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["scan_id", "impact", "severity", "status", "check_id", "delta"],
                name="findings_filter_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=django.contrib.postgres.indexes.GinIndex(
                fields=["text_search"], name="gin_findings_search_idx"
            ),
        ),
        PostgresAddDefaultPartition(
            model_name="Finding",
            name="default",
        ),
        # NOTE: the RLS policy needs to be explicitly set on the partitions
        migrations.AddConstraint(
            model_name="finding",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_finding",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="finding",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_finding_default",
                partition_name="default",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        PostgresCreatePartitionedModel(
            name="ResourceFindingMapping",
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
                (
                    "finding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.finding"
                    ),
                ),
                (
                    "resource",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.resource"
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "resource_finding_mappings",
                "abstract": False,
                "base_manager_name": "objects",
            },
            partitioning_options={
                "method": PostgresPartitioningMethod["RANGE"],
                "key": ["finding_id"],
            },
            bases=(PostgresPartitionedModel,),
            managers=[
                ("objects", PostgresManager()),
            ],
        ),
        migrations.AddField(
            model_name="finding",
            name="resources",
            field=models.ManyToManyField(
                related_name="findings",
                through="api.ResourceFindingMapping",
                to="api.resource",
                verbose_name="Resources associated with the finding",
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcefindingmapping",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "resource_id", "finding_id"),
                name="unique_resource_finding_mappings_by_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="resourcefindingmapping",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_resourcefindingmapping",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        PostgresAddDefaultPartition(
            model_name="resourcefindingmapping",
            name="default",
        ),
        migrations.AddConstraint(
            model_name="resourcefindingmapping",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_resource_finding_mappings_default",
                partition_name="default",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AlterModelOptions(
            name="finding",
            options={},
        ),
        migrations.RunPython(
            ProviderSecretTypeEnumMigration.create_enum_type,
            reverse_code=ProviderSecretTypeEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=ProviderSecretTypeEnum)),
        migrations.CreateModel(
            name="ProviderSecret",
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
                (
                    "name",
                    models.CharField(
                        blank=True,
                        max_length=100,
                        null=True,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                (
                    "secret_type",
                    ProviderSecretTypeEnumField(
                        choices=ProviderSecret.TypeChoices.choices
                    ),
                ),
                ("_secret", models.BinaryField(db_column="secret")),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
                (
                    "provider",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="secret",
                        related_query_name="secret",
                        to="api.provider",
                    ),
                ),
            ],
            options={
                "db_table": "provider_secrets",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="providersecret",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_providersecret",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.RunPython(
            InvitationStateEnumMigration.create_enum_type,
            reverse_code=InvitationStateEnumMigration.drop_enum_type,
        ),
        migrations.RunPython(partial(register_enum, enum_class=InvitationStateEnum)),
        migrations.CreateModel(
            name="Invitation",
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
                ("email", models.EmailField(max_length=254)),
                (
                    "state",
                    InvitationStateEnumField(
                        choices=[
                            ("pending", "Invitation is pending"),
                            ("accepted", "Invitation was accepted by a user"),
                            ("expired", "Invitation expired after the configured time"),
                            ("revoked", "Invitation was revoked by a user"),
                        ],
                        default="pending",
                    ),
                ),
                (
                    "token",
                    models.CharField(
                        unique=True,
                        default=api.db_utils.generate_random_token,
                        editable=False,
                        max_length=14,
                        validators=[django.core.validators.MinLengthValidator(14)],
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(default=api.db_utils.one_week_from_now),
                ),
                (
                    "inviter",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="invitations",
                        related_query_name="invitation",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "invitations",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="invitation",
            constraint=models.UniqueConstraint(
                fields=("tenant", "token", "email"),
                name="unique_tenant_token_email_by_invitation",
            ),
        ),
        migrations.AddConstraint(
            model_name="invitation",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_invitation",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.CreateModel(
            name="ComplianceOverview",
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
                ("compliance_id", models.CharField(max_length=100)),
                ("framework", models.CharField(max_length=100)),
                ("version", models.CharField(blank=True, max_length=50)),
                ("description", models.TextField(blank=True)),
                ("region", models.CharField(blank=True, max_length=50)),
                ("requirements", models.JSONField(default=dict)),
                ("requirements_passed", models.IntegerField(default=0)),
                ("requirements_failed", models.IntegerField(default=0)),
                ("requirements_manual", models.IntegerField(default=0)),
                ("total_requirements", models.IntegerField(default=0)),
            ],
            options={
                "db_table": "compliance_overviews",
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="complianceoverview",
            name="scan",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="compliance_overviews",
                related_query_name="compliance_overview",
                to="api.scan",
            ),
        ),
        migrations.AddField(
            model_name="complianceoverview",
            name="tenant",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
            ),
        ),
        migrations.AddConstraint(
            model_name="complianceoverview",
            constraint=models.UniqueConstraint(
                fields=("tenant", "scan", "compliance_id", "region"),
                name="unique_tenant_scan_region_compliance_by_compliance_overview",
            ),
        ),
        migrations.AddConstraint(
            model_name="complianceoverview",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_complianceoverview",
                statements=["SELECT", "INSERT", "DELETE"],
            ),
        ),
        migrations.AddIndex(
            model_name="complianceoverview",
            index=models.Index(fields=["compliance_id"], name="comp_ov_cp_id_idx"),
        ),
        migrations.AddIndex(
            model_name="complianceoverview",
            index=models.Index(
                fields=["requirements_failed"], name="comp_ov_req_fail_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="complianceoverview",
            index=models.Index(
                fields=["compliance_id", "requirements_failed"],
                name="comp_ov_cp_id_req_fail_idx",
            ),
        ),
        migrations.CreateModel(
            name="ScanSummary",
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
                ("check_id", models.CharField(max_length=100)),
                ("service", models.TextField()),
                (
                    "severity",
                    api.db_utils.SeverityEnumField(
                        choices=[
                            ("critical", "Critical"),
                            ("high", "High"),
                            ("medium", "Medium"),
                            ("low", "Low"),
                            ("informational", "Informational"),
                        ]
                    ),
                ),
                ("region", models.TextField()),
                ("_pass", models.IntegerField(db_column="pass", default=0)),
                ("fail", models.IntegerField(default=0)),
                ("muted", models.IntegerField(default=0)),
                ("total", models.IntegerField(default=0)),
                ("new", models.IntegerField(default=0)),
                ("changed", models.IntegerField(default=0)),
                ("unchanged", models.IntegerField(default=0)),
                ("fail_new", models.IntegerField(default=0)),
                ("fail_changed", models.IntegerField(default=0)),
                ("pass_new", models.IntegerField(default=0)),
                ("pass_changed", models.IntegerField(default=0)),
                ("muted_new", models.IntegerField(default=0)),
                ("muted_changed", models.IntegerField(default=0)),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="aggregations",
                        related_query_name="aggregation",
                        to="api.scan",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "scan_summaries",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="scansummary",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scansummary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="scansummary",
            constraint=models.UniqueConstraint(
                fields=("tenant", "scan", "check_id", "service", "severity", "region"),
                name="unique_scan_summary",
            ),
        ),
    ]
