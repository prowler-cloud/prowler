import json
import re
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.core.validators import MinLengthValidator
from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django_celery_results.models import TaskResult
from psqlextra.manager import PostgresManager
from psqlextra.models import PostgresPartitionedModel
from psqlextra.types import PostgresPartitioningMethod
from uuid6 import uuid7

from api.db_utils import (
    CustomUserManager,
    FindingDeltaEnumField,
    InvitationStateEnumField,
    MemberRoleEnumField,
    ProviderEnumField,
    ProviderSecretTypeEnumField,
    ScanTriggerEnumField,
    SeverityEnumField,
    StateEnumField,
    StatusEnumField,
    enum_to_choices,
    generate_random_token,
    one_week_from_now,
)
from api.exceptions import ModelValidationError
from api.rls import (
    BaseSecurityConstraint,
    RowLevelSecurityConstraint,
    RowLevelSecurityProtectedModel,
    Tenant,
)
from prowler.lib.check.models import Severity

fernet = Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())

# Convert Prowler Severity enum to Django TextChoices
SeverityChoices = enum_to_choices(Severity)


class StatusChoices(models.TextChoices):
    """
    This list is based on the finding status in the Prowler CLI.

    However, it adds another state, MUTED, which is not in the CLI.
    """

    FAIL = "FAIL", _("Fail")
    PASS = "PASS", _("Pass")
    MANUAL = "MANUAL", _("Manual")
    MUTED = "MUTED", _("Muted")


class StateChoices(models.TextChoices):
    AVAILABLE = "available", _("Available")
    SCHEDULED = "scheduled", _("Scheduled")
    EXECUTING = "executing", _("Executing")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")
    CANCELLED = "cancelled", _("Cancelled")


class ActiveProviderManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(self.active_provider_filter())

    def active_provider_filter(self):
        if self.model is Provider:
            return Q(is_deleted=False)
        elif self.model in [Finding, ComplianceOverview, ScanSummary]:
            return Q(scan__provider__is_deleted=False)
        else:
            return Q(provider__is_deleted=False)


class ActiveProviderPartitionedManager(PostgresManager, ActiveProviderManager):
    def get_queryset(self):
        return super().get_queryset().filter(self.active_provider_filter())


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=150, validators=[MinLengthValidator(3)])
    email = models.EmailField(
        max_length=254,
        unique=True,
        help_text="Case insensitive",
        error_messages={"unique": "Please check the email address and try again."},
    )
    company_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True, editable=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    objects = CustomUserManager()

    def is_member_of_tenant(self, tenant_id):
        return self.memberships.filter(tenant_id=tenant_id).exists()

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    class Meta:
        db_table = "users"

        constraints = [
            BaseSecurityConstraint(
                name="statements_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            )
        ]

    class JSONAPIMeta:
        resource_name = "users"


class Membership(models.Model):
    class RoleChoices(models.TextChoices):
        OWNER = "owner", _("Owner")
        MEMBER = "member", _("Member")

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memberships",
        related_query_name="membership",
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="memberships",
        related_query_name="membership",
    )
    role = MemberRoleEnumField(choices=RoleChoices.choices, default=RoleChoices.MEMBER)
    date_joined = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        db_table = "memberships"

        constraints = [
            models.UniqueConstraint(
                fields=("user", "tenant"),
                name="unique_resources_by_membership",
            ),
            BaseSecurityConstraint(
                name="statements_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "memberships"


class Provider(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    class ProviderChoices(models.TextChoices):
        AWS = "aws", _("AWS")
        AZURE = "azure", _("Azure")
        GCP = "gcp", _("GCP")
        KUBERNETES = "kubernetes", _("Kubernetes")

    @staticmethod
    def validate_aws_uid(value):
        if not re.match(r"^\d{12}$", value):
            raise ModelValidationError(
                detail="AWS provider ID must be exactly 12 digits.",
                code="aws-uid",
                pointer="/data/attributes/uid",
            )

    @staticmethod
    def validate_azure_uid(value):
        try:
            val = UUID(value, version=4)
            if str(val) != value:
                raise ValueError
        except ValueError:
            raise ModelValidationError(
                detail="Azure provider ID must be a valid UUID.",
                code="azure-uid",
                pointer="/data/attributes/uid",
            )

    @staticmethod
    def validate_gcp_uid(value):
        if not re.match(r"^[a-z][a-z0-9-]{5,29}$", value):
            raise ModelValidationError(
                detail="GCP provider ID must be 6 to 30 characters, start with a letter, and contain only lowercase "
                "letters, numbers, and hyphens.",
                code="gcp-uid",
                pointer="/data/attributes/uid",
            )

    @staticmethod
    def validate_kubernetes_uid(value):
        if not re.match(
            r"(^[a-z0-9]([-a-z0-9]{1,61}[a-z0-9])?$)|(^arn:aws(-cn|-us-gov|-iso|-iso-b)?:[a-zA-Z0-9\-]+:([a-z]{2}-[a-z]+-\d{1})?:(\d{12})?:[a-zA-Z0-9\-_\/:\.\*]+(:\d+)?$)",
            value,
        ):
            raise ModelValidationError(
                detail="The value must either be a valid Kubernetes UID (up to 63 characters, "
                "starting and ending with a lowercase letter or number, containing only "
                "lowercase alphanumeric characters and hyphens) or a valid EKS ARN.",
                code="kubernetes-uid",
                pointer="/data/attributes/uid",
            )

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    is_deleted = models.BooleanField(default=False)
    provider = ProviderEnumField(
        choices=ProviderChoices.choices, default=ProviderChoices.AWS
    )
    uid = models.CharField(
        "Unique identifier for the provider, set by the provider",
        max_length=63,
        blank=False,
        validators=[MinLengthValidator(3)],
    )
    alias = models.CharField(
        blank=True, null=True, max_length=100, validators=[MinLengthValidator(3)]
    )
    connected = models.BooleanField(null=True, blank=True)
    connection_last_checked_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    scanner_args = models.JSONField(default=dict, blank=True)

    def clean(self):
        super().clean()
        getattr(self, f"validate_{self.provider}_uid")(self.uid)

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "providers"

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "provider", "uid", "is_deleted"),
                name="unique_provider_uids",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "providers"


class ProviderGroup(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=255)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    providers = models.ManyToManyField(
        Provider, through="ProviderGroupMembership", related_name="provider_groups"
    )

    class Meta:
        db_table = "provider_groups"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant_id", "name"],
                name="unique_group_name_per_tenant",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "provider-groups"


class ProviderGroupMembership(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
    )
    provider_group = models.ForeignKey(
        ProviderGroup,
        on_delete=models.CASCADE,
    )
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        db_table = "provider_group_memberships"
        constraints = [
            models.UniqueConstraint(
                fields=["provider_id", "provider_group"],
                name="unique_provider_group_membership",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "provider-group-memberships"


class Task(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    task_runner_task = models.OneToOneField(
        TaskResult,
        on_delete=models.CASCADE,
        related_name="task",
        related_query_name="task",
        null=True,
        blank=True,
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "tasks"

        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

        indexes = [
            models.Index(
                fields=["id", "task_runner_task"],
                name="tasks_id_trt_id_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "tasks"


class Scan(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    class TriggerChoices(models.TextChoices):
        SCHEDULED = "scheduled", _("Scheduled")
        MANUAL = "manual", _("Manual")

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    name = models.CharField(
        blank=True, null=True, max_length=100, validators=[MinLengthValidator(3)]
    )
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="scans",
        related_query_name="scan",
    )
    task = models.ForeignKey(
        Task,
        on_delete=models.CASCADE,
        related_name="scans",
        related_query_name="scan",
        null=True,
        blank=True,
    )
    trigger = ScanTriggerEnumField(
        choices=TriggerChoices.choices,
    )
    state = StateEnumField(choices=StateChoices.choices, default=StateChoices.AVAILABLE)
    unique_resource_count = models.IntegerField(default=0)
    progress = models.IntegerField(default=0)
    scanner_args = models.JSONField(default=dict)
    duration = models.IntegerField(null=True, blank=True)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    next_scan_at = models.DateTimeField(null=True, blank=True)
    # TODO: mutelist foreign key

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "scans"

        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

        indexes = [
            models.Index(
                fields=["provider", "state", "trigger", "scheduled_at"],
                name="scans_prov_state_trig_sche_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "scans"


class ResourceTag(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    key = models.TextField(blank=False)
    value = models.TextField(blank=False)

    text_search = models.GeneratedField(
        expression=SearchVector("key", weight="A", config="simple")
        + SearchVector("value", weight="B", config="simple"),
        output_field=SearchVectorField(),
        db_persist=True,
        null=True,
        editable=False,
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resource_tags"

        indexes = [
            GinIndex(fields=["text_search"], name="gin_resource_tags_search_idx"),
        ]

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "key", "value"),
                name="unique_resource_tags_by_tenant_key_value",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]


class Resource(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="resources",
        related_query_name="resource",
    )

    uid = models.TextField(
        "Unique identifier for the resource, set by the provider", blank=False
    )
    name = models.TextField("Name of the resource, as set in the provider", blank=False)
    region = models.TextField(
        "Location of the resource, as set by the provider", blank=False
    )
    service = models.TextField(
        "Service of the resource, as set by the provider", blank=False
    )
    type = models.TextField("Type of the resource, as set by the provider", blank=False)

    text_search = models.GeneratedField(
        expression=SearchVector("uid", weight="A", config="simple")
        + SearchVector("name", weight="B", config="simple")
        + SearchVector("region", weight="C", config="simple")
        + SearchVector("service", "type", weight="D", config="simple"),
        output_field=SearchVectorField(),
        db_persist=True,
        null=True,
        editable=False,
    )

    tags = models.ManyToManyField(
        ResourceTag,
        verbose_name="Tags associated with the resource, by provider",
        through="ResourceTagMapping",
    )

    def get_tags(self) -> dict:
        return {tag.key: tag.value for tag in self.tags.all()}

    def clear_tags(self):
        self.tags.clear()
        self.save()

    def upsert_or_delete_tags(self, tags: list[ResourceTag] | None):
        if tags is None:
            self.clear_tags()
            return

        # Add new relationships with the tenant_id field
        for tag in tags:
            ResourceTagMapping.objects.update_or_create(
                tag=tag, resource=self, tenant_id=self.tenant_id
            )

        # Save the instance
        self.save()

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resources"

        indexes = [
            models.Index(
                fields=["uid", "region", "service", "name"],
                name="resource_uid_reg_serv_name_idx",
            ),
            GinIndex(fields=["text_search"], name="gin_resources_search_idx"),
        ]

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "provider_id", "uid"),
                name="unique_resources_by_provider",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "resources"


class ResourceTagMapping(RowLevelSecurityProtectedModel):
    # NOTE that we don't really need a primary key here,
    #      but everything is easier with django if we do
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    tag = models.ForeignKey(ResourceTag, on_delete=models.CASCADE)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resource_tag_mappings"

        # django will automatically create indexes for:
        #   - resource_id
        #   - tag_id
        #   - tenant_id
        #   - id

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "resource_id", "tag_id"),
                name="unique_resource_tag_mappings_by_tenant",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]


class Finding(PostgresPartitionedModel, RowLevelSecurityProtectedModel):
    """
    Defines the Finding model.

    Findings uses a partitioned table to store findings. The partitions are created based on the UUIDv7 `id` field.

    Note when creating migrations, you must use `python manage.py pgmakemigrations` to create the migrations.
    """

    objects = ActiveProviderPartitionedManager()
    all_objects = models.Manager()

    class PartitioningMeta:
        method = PostgresPartitioningMethod.RANGE
        key = ["id"]

    class DeltaChoices(models.TextChoices):
        NEW = "new", _("New")
        CHANGED = "changed", _("Changed")

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    uid = models.CharField(max_length=300)
    delta = FindingDeltaEnumField(
        choices=DeltaChoices.choices,
        blank=True,
        null=True,
    )

    status = StatusEnumField(choices=StatusChoices)
    status_extended = models.TextField(blank=True, null=True)

    severity = SeverityEnumField(choices=SeverityChoices)

    impact = SeverityEnumField(choices=SeverityChoices)
    impact_extended = models.TextField(blank=True, null=True)

    raw_result = models.JSONField(default=dict)
    tags = models.JSONField(default=dict, null=True, blank=True)
    check_id = models.CharField(max_length=100, blank=False, null=False)
    check_metadata = models.JSONField(default=dict, null=False)

    # Relationships
    scan = models.ForeignKey(to=Scan, related_name="findings", on_delete=models.CASCADE)

    # many-to-many Resources. Relationship is defined on Resource
    resources = models.ManyToManyField(
        Resource,
        verbose_name="Resources associated with the finding",
        through="ResourceFindingMapping",
        related_name="findings",
    )

    # TODO: Add resource search
    text_search = models.GeneratedField(
        expression=SearchVector(
            "impact_extended", "status_extended", weight="A", config="simple"
        ),
        output_field=SearchVectorField(),
        db_persist=True,
        null=True,
        editable=False,
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "findings"

        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "UPDATE", "INSERT", "DELETE"],
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s_default",
                partition_name="default",
                statements=["SELECT", "UPDATE", "INSERT", "DELETE"],
            ),
        ]

        indexes = [
            models.Index(fields=["uid"], name="findings_uid_idx"),
            models.Index(
                fields=[
                    "scan_id",
                    "impact",
                    "severity",
                    "status",
                    "check_id",
                    "delta",
                ],
                name="findings_filter_idx",
            ),
            GinIndex(fields=["text_search"], name="gin_findings_search_idx"),
        ]

    class JSONAPIMeta:
        resource_name = "findings"

    def add_resources(self, resources: list[Resource] | None):
        # Add new relationships with the tenant_id field
        for resource in resources:
            ResourceFindingMapping.objects.update_or_create(
                resource=resource, finding=self, tenant_id=self.tenant_id
            )

        # Save the instance
        self.save()


class ResourceFindingMapping(PostgresPartitionedModel, RowLevelSecurityProtectedModel):
    """
    Defines the ResourceFindingMapping model.

    ResourceFindingMapping is used to map a Finding to a Resource.

    It follows the same partitioning strategy as the Finding model.
    """

    # NOTE that we don't really need a primary key here,
    #      but everything is easier with django if we do
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE)

    class PartitioningMeta:
        method = PostgresPartitioningMethod.RANGE
        key = ["finding_id"]

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resource_finding_mappings"
        base_manager_name = "objects"
        abstract = False

        # django will automatically create indexes for:
        #   - resource_id
        #   - finding_id
        #   - tenant_id
        #   - id

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "resource_id", "finding_id"),
                name="unique_resource_finding_mappings_by_tenant",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            RowLevelSecurityConstraint(
                "tenant_id",
                name=f"rls_on_{db_table}_default",
                partition_name="default",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]


class ProviderSecret(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    class TypeChoices(models.TextChoices):
        STATIC = "static", _("Key-value pairs")
        ROLE = "role", _("Role assumption")

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(
        blank=True, null=True, max_length=100, validators=[MinLengthValidator(3)]
    )
    secret_type = ProviderSecretTypeEnumField(choices=TypeChoices.choices)
    _secret = models.BinaryField(db_column="secret")
    provider = models.OneToOneField(
        Provider,
        on_delete=models.CASCADE,
        related_name="secret",
        related_query_name="secret",
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "provider_secrets"

        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "provider-secrets"

    @property
    def secret(self):
        if isinstance(self._secret, memoryview):
            encrypted_bytes = self._secret.tobytes()
        elif isinstance(self._secret, str):
            encrypted_bytes = self._secret.encode()
        else:
            encrypted_bytes = self._secret
        decrypted_data = fernet.decrypt(encrypted_bytes)
        return json.loads(decrypted_data.decode())

    @secret.setter
    def secret(self, value):
        encrypted_data = fernet.encrypt(json.dumps(value).encode())
        self._secret = encrypted_data


class Invitation(RowLevelSecurityProtectedModel):
    class State(models.TextChoices):
        PENDING = "pending", _("Invitation is pending")
        ACCEPTED = "accepted", _("Invitation was accepted by a user")
        EXPIRED = "expired", _("Invitation expired after the configured time")
        REVOKED = "revoked", _("Invitation was revoked by a user")

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    email = models.EmailField(max_length=254, blank=False, null=False)
    state = InvitationStateEnumField(choices=State.choices, default=State.PENDING)
    token = models.CharField(
        max_length=14,
        unique=True,
        default=generate_random_token,
        editable=False,
        blank=False,
        null=False,
        validators=[MinLengthValidator(14)],
    )
    expires_at = models.DateTimeField(default=one_week_from_now)
    inviter = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name="invitations",
        related_query_name="invitation",
        null=True,
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "invitations"

        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "token", "email"),
                name="unique_tenant_token_email_by_invitation",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "invitations"


class ComplianceOverview(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    compliance_id = models.CharField(max_length=100, blank=False, null=False)
    framework = models.CharField(max_length=100, blank=False, null=False)
    version = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)
    region = models.CharField(max_length=50, blank=True)
    requirements = models.JSONField(default=dict)
    requirements_passed = models.IntegerField(default=0)
    requirements_failed = models.IntegerField(default=0)
    requirements_manual = models.IntegerField(default=0)
    total_requirements = models.IntegerField(default=0)

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="compliance_overviews",
        related_query_name="compliance_overview",
        null=True,
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "compliance_overviews"

        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "scan", "compliance_id", "region"),
                name="unique_tenant_scan_region_compliance_by_compliance_overview",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "DELETE"],
            ),
        ]
        indexes = [
            models.Index(fields=["compliance_id"], name="comp_ov_cp_id_idx"),
            models.Index(fields=["requirements_failed"], name="comp_ov_req_fail_idx"),
            models.Index(
                fields=["compliance_id", "requirements_failed"],
                name="comp_ov_cp_id_req_fail_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "compliance-overviews"


class ScanSummary(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()
    all_objects = models.Manager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    check_id = models.CharField(max_length=100, blank=False, null=False)
    service = models.TextField(blank=False)
    severity = SeverityEnumField(choices=SeverityChoices)
    region = models.TextField(blank=False)
    _pass = models.IntegerField(db_column="pass", default=0)
    fail = models.IntegerField(default=0)
    muted = models.IntegerField(default=0)
    total = models.IntegerField(default=0)
    new = models.IntegerField(default=0)
    changed = models.IntegerField(default=0)
    unchanged = models.IntegerField(default=0)

    fail_new = models.IntegerField(default=0)
    fail_changed = models.IntegerField(default=0)
    pass_new = models.IntegerField(default=0)
    pass_changed = models.IntegerField(default=0)
    muted_new = models.IntegerField(default=0)
    muted_changed = models.IntegerField(default=0)

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="aggregations",
        related_query_name="aggregation",
    )

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "scan_summaries"

        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "scan", "check_id", "service", "severity", "region"),
                name="unique_scan_summary",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "scan-summaries"
