# Example: Advanced Model Patterns
# Source: api/src/backend/api/models.py, api/src/backend/api/rls.py

from uuid import uuid4

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from psqlextra.models import PostgresPartitionedModel
from psqlextra.types import PostgresPartitioningMethod
from uuid6 import uuid7

from api.rls import RowLevelSecurityConstraint, RowLevelSecurityProtectedModel

# =============================================================================
# 1. Provider Model - Soft Delete with Custom Managers
# =============================================================================


class ActiveProviderManager(models.Manager):
    """Manager that filters out soft-deleted providers."""

    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class Provider(RowLevelSecurityProtectedModel):
    """
    Cloud provider configuration.

    Key patterns:
    - Soft delete via is_deleted flag
    - Two managers: objects (active only), all_objects (all)
    - UID validation varies by provider type
    """

    # Dual managers for soft delete
    objects = ActiveProviderManager()  # Default: only active
    all_objects = models.Manager()  # All including deleted

    class ProviderChoices(models.TextChoices):
        AWS = "aws", _("AWS")
        AZURE = "azure", _("Azure")
        GCP = "gcp", _("GCP")
        KUBERNETES = "kubernetes", _("Kubernetes")
        M365 = "m365", _("M365")
        GITHUB = "github", _("GitHub")
        MONGODBATLAS = "mongodbatlas", _("MongoDB Atlas")
        IAC = "iac", _("IaC")
        ORACLECLOUD = "oraclecloud", _("Oracle Cloud Infrastructure")
        ALIBABACLOUD = "alibabacloud", _("Alibaba Cloud")

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    is_deleted = models.BooleanField(default=False)

    provider = models.CharField(
        max_length=50,
        choices=ProviderChoices.choices,
        default=ProviderChoices.AWS,
    )
    uid = models.CharField(max_length=255)  # Account ID, subscription ID, project ID
    alias = models.CharField(max_length=255, blank=True)
    connected = models.BooleanField(default=False)
    connection_last_checked_at = models.DateTimeField(null=True, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "providers"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_provider",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            # Unique constraint with condition (only for non-deleted)
            models.UniqueConstraint(
                fields=["tenant_id", "provider", "uid"],
                condition=Q(is_deleted=False),
                name="unique_provider_uid_per_tenant",
            ),
        ]
        indexes = [
            models.Index(fields=["tenant_id", "provider"], name="prov_tenant_type_idx"),
            models.Index(
                fields=["tenant_id", "connected"], name="prov_tenant_conn_idx"
            ),
        ]

    class JSONAPIMeta:
        resource_name = "providers"


# =============================================================================
# 2. Finding Model - Partitioned Table with UUIDv7
# =============================================================================


class ActiveProviderPartitionedManager(models.Manager):
    """Manager for partitioned tables that filters by active providers."""

    def get_queryset(self):
        return super().get_queryset().filter(scan__provider__is_deleted=False)


class Finding(PostgresPartitionedModel, RowLevelSecurityProtectedModel):
    """
    Security finding from a scan.

    Key patterns:
    - Partitioned by UUIDv7 range (contains timestamp)
    - Denormalized arrays for fast filtering
    - Full-text search via SearchVectorField
    """

    objects = ActiveProviderPartitionedManager()
    all_objects = models.Manager()

    # UUIDv7 for time-based partitioning
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    scan = models.ForeignKey("Scan", on_delete=models.CASCADE, related_name="findings")

    # Core fields
    uid = models.CharField(max_length=255)
    check_id = models.CharField(max_length=255)
    status = models.CharField(max_length=50)  # PASS, FAIL, MANUAL
    severity = models.CharField(
        max_length=50
    )  # critical, high, medium, low, informational
    muted = models.BooleanField(default=False)
    delta = models.CharField(max_length=50, null=True)  # new, changed, None

    # Denormalized for fast filtering (avoid JOINs)
    resource_regions = models.JSONField(default=list)  # ["us-east-1", "eu-west-1"]
    resource_services = models.JSONField(default=list)  # ["s3", "ec2"]
    resource_types = models.JSONField(default=list)  # ["AWS::S3::Bucket"]
    categories = models.JSONField(default=list)  # ["security", "compliance"]

    # Full-text search
    text_search = SearchVectorField(null=True)

    # Many-to-many with resources
    resources = models.ManyToManyField(
        "Resource",
        through="ResourceFindingMapping",
        related_name="findings",
    )

    class PartitioningMeta:
        """PostgreSQL table partitioning configuration."""

        method = PostgresPartitioningMethod.RANGE
        key = ["id"]

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "findings"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_finding",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
        indexes = [
            # Always put tenant_id first for RLS
            models.Index(
                fields=["tenant_id", "scan_id"],
                name="find_tenant_scan_idx",
            ),
            models.Index(
                fields=["tenant_id", "scan_id", "severity"],
                name="find_tenant_scan_sev_idx",
            ),
            # Partial index for common filter
            models.Index(
                fields=["tenant_id", "id"],
                name="find_delta_new_idx",
                condition=Q(delta="new"),
            ),
            # GIN for full-text search
            GinIndex(fields=["text_search"], name="find_search_gin_idx"),
            # GIN for array fields
            GinIndex(fields=["resource_regions"], name="find_regions_gin_idx"),
            GinIndex(fields=["categories"], name="find_categories_gin_idx"),
        ]


# =============================================================================
# 3. Resource Model - Full-Text Search with Generated Field
# =============================================================================


class Resource(RowLevelSecurityProtectedModel):
    """
    Cloud resource discovered during scan.

    Key patterns:
    - SearchVectorField with GeneratedField for auto-update
    - Soft delete via manager (follows active provider)
    """

    objects = ActiveProviderPartitionedManager()
    all_objects = models.Manager()

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)

    uid = models.CharField(max_length=1024)  # ARN, resource ID
    name = models.CharField(max_length=512, blank=True)
    region = models.CharField(max_length=100)
    service = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=255)

    # Auto-generated search vector (PostgreSQL GeneratedField)
    text_search = SearchVectorField(null=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resources"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_resource",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider_id", "uid"],
                name="unique_resource_uid_per_provider",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider_id"],
                name="res_tenant_prov_idx",
            ),
            models.Index(
                fields=["tenant_id", "service", "region"],
                name="res_tenant_svc_reg_idx",
            ),
            GinIndex(fields=["text_search"], name="res_search_gin_idx"),
        ]


# =============================================================================
# 4. Summary Tables - Denormalization for Performance
# =============================================================================


class ScanSummary(RowLevelSecurityProtectedModel):
    """
    Pre-aggregated scan results by check/severity/region.

    Populated by perform_scan_summary_task after each scan.
    Use this instead of aggregating Finding table directly.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)

    scan = models.ForeignKey("Scan", on_delete=models.CASCADE)
    check_id = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    severity = models.CharField(max_length=50)
    region = models.CharField(max_length=255)

    # Pre-computed counts
    _pass = models.IntegerField(default=0)  # 'pass' is reserved keyword
    fail = models.IntegerField(default=0)
    muted = models.IntegerField(default=0)
    total = models.IntegerField(default=0)
    new = models.IntegerField(default=0)
    changed = models.IntegerField(default=0)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "scan_summaries"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_scan_summary",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=[
                    "tenant_id",
                    "scan_id",
                    "check_id",
                    "service",
                    "severity",
                    "region",
                ],
                name="unique_scan_summary",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "scan_id"],
                name="ss_tenant_scan_idx",
            ),
            models.Index(
                fields=["tenant_id", "scan_id", "severity"],
                name="ss_tenant_scan_sev_idx",
            ),
        ]


class DailySeveritySummary(RowLevelSecurityProtectedModel):
    """
    Daily severity counts per provider for trending dashboards.

    Populated by aggregate_daily_severity_task.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    date = models.DateField()

    critical = models.IntegerField(default=0)
    high = models.IntegerField(default=0)
    medium = models.IntegerField(default=0)
    low = models.IntegerField(default=0)
    informational = models.IntegerField(default=0)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "daily_severity_summaries"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_daily_severity",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider_id", "date"],
                name="unique_daily_severity_per_provider",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider_id", "date"],
                name="dss_tenant_prov_date_idx",
            ),
        ]


# =============================================================================
# 5. RLS Infrastructure
# =============================================================================


class RowLevelSecurityProtectedModel(models.Model):
    """
    Abstract base for all tenant-scoped models.

    All queries are automatically filtered by tenant_id via PostgreSQL RLS.
    """

    tenant = models.ForeignKey(
        "Tenant",
        on_delete=models.CASCADE,
        db_column="tenant_id",
    )

    class Meta:
        abstract = True


class RowLevelSecurityConstraint(models.BaseConstraint):
    """
    Django constraint that creates PostgreSQL RLS policy.

    Creates:
    - POLICY for SELECT, INSERT, UPDATE, DELETE
    - Filters by current_setting('api.tenant_id')
    """

    def __init__(self, field: str, name: str, statements: list):
        self.target_field = field
        self.statements = statements
        super().__init__(name=name)

    def create_sql(self, model, schema_editor):
        """Generate CREATE POLICY SQL."""
        table = model._meta.db_table
        policies = []

        for stmt in self.statements:
            policy_name = f"{self.name}_{stmt.lower()}"
            if stmt == "INSERT":
                check = f"WITH CHECK ({self.target_field} = current_setting('api.tenant_id')::uuid)"
            else:
                check = f"USING ({self.target_field} = current_setting('api.tenant_id')::uuid)"

            policies.append(
                f"CREATE POLICY {policy_name} ON {table} FOR {stmt} {check}"
            )

        # Enable RLS
        policies.insert(0, f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        policies.insert(1, f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

        return policies


# =============================================================================
# 6. Provider Secrets - Encrypted Fields
# =============================================================================


class ProviderSecret(RowLevelSecurityProtectedModel):
    """
    Encrypted credentials for provider authentication.

    Uses django-encrypted-model-fields for at-rest encryption.
    Each provider type has different required fields.
    """

    provider = models.OneToOneField(
        Provider,
        on_delete=models.CASCADE,
        related_name="secret",
    )

    # AWS credentials
    role_arn = models.CharField(max_length=2048, blank=True)
    external_id = models.CharField(max_length=1224, blank=True)
    aws_access_key_id = EncryptedCharField(max_length=128, blank=True)
    aws_secret_access_key = EncryptedCharField(max_length=128, blank=True)
    aws_session_token = EncryptedCharField(max_length=2048, blank=True)

    # Azure credentials
    client_id = EncryptedCharField(max_length=36, blank=True)
    client_secret = EncryptedCharField(max_length=255, blank=True)
    tenant_id_azure = models.CharField(max_length=36, blank=True)

    # GCP credentials
    service_account_key = EncryptedTextField(blank=True)

    # Kubernetes credentials
    kubeconfig_content = EncryptedTextField(blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "provider_secrets"


# =============================================================================
# 7. Scan Model - Task Association
# =============================================================================


class Scan(RowLevelSecurityProtectedModel):
    """
    Scan execution record.

    Key patterns:
    - Links to Provider and Task (for status tracking)
    - State machine: AVAILABLE -> EXECUTING -> COMPLETED/FAILED
    """

    objects = ActiveProviderManager()
    all_objects = models.Manager()

    class TriggerChoices(models.TextChoices):
        MANUAL = "manual", _("Manual")
        SCHEDULED = "scheduled", _("Scheduled")

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    task = models.ForeignKey("APITask", on_delete=models.SET_NULL, null=True)

    trigger = models.CharField(
        max_length=50,
        choices=TriggerChoices.choices,
        default=TriggerChoices.MANUAL,
    )
    state = models.CharField(max_length=50, default="available")

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Scan configuration
    checks_to_execute = models.JSONField(default=list, blank=True)
    regions_to_scan = models.JSONField(default=list, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "scans"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_scan",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider_id", "state"],
                name="scan_tenant_prov_state_idx",
            ),
            models.Index(
                fields=["tenant_id", "inserted_at"],
                name="scan_tenant_inserted_idx",
            ),
            # Partial index for completed scans (common query)
            models.Index(
                fields=["tenant_id", "provider_id", "inserted_at"],
                name="scan_completed_idx",
                condition=Q(state="completed"),
            ),
        ]
