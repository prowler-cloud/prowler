import re
from uuid import uuid4, UUID

from django.core.validators import MinLengthValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from uuid6 import uuid7

from api.db_utils import ProviderEnumField, StateEnumField, ScanTriggerEnumField
from api.exceptions import ModelValidationError
from api.rls import RowLevelSecurityConstraint
from api.rls import RowLevelSecurityProtectedModel


class StateChoices(models.TextChoices):
    AVAILABLE = "available", _("Available")
    SCHEDULED = "scheduled", _("Scheduled")
    EXECUTING = "executing", _("Executing")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")
    CANCELLED = "cancelled", _("Cancelled")


class Provider(RowLevelSecurityProtectedModel):
    class ProviderChoices(models.TextChoices):
        AWS = "aws", _("AWS")
        AZURE = "azure", _("Azure")
        GCP = "gcp", _("GCP")
        KUBERNETES = "kubernetes", _("Kubernetes")

    @staticmethod
    def validate_aws_provider_id(value):
        if not re.match(r"^\d{12}$", value):
            raise ModelValidationError(
                detail="AWS provider ID must be exactly 12 digits.",
                code="aws-provider-id",
                pointer="/data/attributes/provider_id",
            )

    @staticmethod
    def validate_azure_provider_id(value):
        try:
            val = UUID(value, version=4)
            if str(val) != value:
                raise ValueError
        except ValueError:
            raise ModelValidationError(
                detail="Azure provider ID must be a valid UUID.",
                code="azure-provider-id",
                pointer="/data/attributes/provider_id",
            )

    @staticmethod
    def validate_gcp_provider_id(value):
        if not re.match(r"^[a-z][a-z0-9-]{5,29}$", value):
            raise ModelValidationError(
                detail="GCP provider ID must be 6 to 30 characters, start with a letter, and contain only lowercase "
                "letters, numbers, and hyphens.",
                code="gcp-provider-id",
                pointer="/data/attributes/provider_id",
            )

    @staticmethod
    def validate_kubernetes_provider_id(value):
        if not re.match(r"^[a-z0-9]([-a-z0-9]{1,61}[a-z0-9])?$", value):
            raise ModelValidationError(
                detail="K8s provider ID must be up to 63 characters, start and end with a lowercase letter or number, "
                "and contain only lowercase alphanumeric characters and hyphens.",
                code="kubernetes-provider-id",
                pointer="/data/attributes/provider_id",
            )

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = ProviderEnumField(
        choices=ProviderChoices.choices, default=ProviderChoices.AWS
    )
    provider_id = models.CharField(max_length=63, validators=[MinLengthValidator(3)])
    alias = models.CharField(
        blank=True, null=True, max_length=100, validators=[MinLengthValidator(3)]
    )
    connected = models.BooleanField(null=True, blank=True)
    connection_last_checked_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    scanner_args = models.JSONField(default=dict, blank=True)

    def clean(self):
        super().clean()
        getattr(self, f"validate_{self.provider}_provider_id")(self.provider_id)

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "providers"

        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "provider", "provider_id"),
                name="unique_provider_ids",
            ),
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]


class Scan(RowLevelSecurityProtectedModel):
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
    # TODO: task foreign key
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
                name="scans_prov_state_type_sche_idx",
            ),
        ]
