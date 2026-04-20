from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from config.env import env
from tasks.jobs.attack_paths import aws

# Batch size for Neo4j write operations (resource labeling, cleanup)
BATCH_SIZE = env.int("ATTACK_PATHS_BATCH_SIZE", 1000)
# Batch size for Postgres findings fetch (keyset pagination page size)
FINDINGS_BATCH_SIZE = env.int("ATTACK_PATHS_FINDINGS_BATCH_SIZE", 1000)
# Batch size for temp-to-tenant graph sync (nodes and relationships per cursor page)
SYNC_BATCH_SIZE = env.int("ATTACK_PATHS_SYNC_BATCH_SIZE", 1000)

# Neo4j internal labels (Prowler-specific, not provider-specific)
# - `Internet`: Singleton node representing external internet access for exposed-resource queries
# - `ProwlerFinding`: Label for finding nodes created by Prowler and linked to cloud resources
# - `_ProviderResource`: Added to ALL synced nodes for provider isolation and drop/query ops
INTERNET_NODE_LABEL = "Internet"
PROWLER_FINDING_LABEL = "ProwlerFinding"
PROVIDER_RESOURCE_LABEL = "_ProviderResource"

# Dynamic isolation labels that contain entity UUIDs and are added to every synced node during sync
# Format: _Tenant_{uuid_no_hyphens}, _Provider_{uuid_no_hyphens}
TENANT_LABEL_PREFIX = "_Tenant_"
PROVIDER_LABEL_PREFIX = "_Provider_"
DYNAMIC_ISOLATION_PREFIXES = [TENANT_LABEL_PREFIX, PROVIDER_LABEL_PREFIX]


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration for a cloud provider's Attack Paths integration."""

    name: str
    root_node_label: str  # e.g., "AWSAccount"
    uid_field: str  # e.g., "arn"
    # Label for resources connected to the account node, enabling indexed finding lookups.
    resource_label: str  # e.g., "_AWSResource"
    ingestion_function: Callable


# Provider Configurations
# -----------------------

AWS_CONFIG = ProviderConfig(
    name="aws",
    root_node_label="AWSAccount",
    uid_field="arn",
    resource_label="_AWSResource",
    ingestion_function=aws.start_aws_ingestion,
)

PROVIDER_CONFIGS: dict[str, ProviderConfig] = {
    "aws": AWS_CONFIG,
}

# Labels added by Prowler that should be filtered from API responses
# Derived from provider configs + common internal labels
INTERNAL_LABELS: list[str] = [
    "Tenant",  # From Cartography, but it looks like it's ours
    PROVIDER_RESOURCE_LABEL,
    *[config.resource_label for config in PROVIDER_CONFIGS.values()],
]

# Provider isolation properties
PROVIDER_ELEMENT_ID_PROPERTY = "_provider_element_id"

PROVIDER_ISOLATION_PROPERTIES: list[str] = [
    PROVIDER_ELEMENT_ID_PROPERTY,
]

# Cartography bookkeeping metadata
CARTOGRAPHY_METADATA_PROPERTIES: list[str] = [
    "lastupdated",
    "firstseen",
    "_module_name",
    "_module_version",
]

INTERNAL_PROPERTIES: list[str] = [
    *PROVIDER_ISOLATION_PROPERTIES,
    *CARTOGRAPHY_METADATA_PROPERTIES,
]


# Provider Config Accessors
# -------------------------


def is_provider_available(provider_type: str) -> bool:
    """Check if a provider type is available for Attack Paths scans."""
    return provider_type in PROVIDER_CONFIGS


def get_cartography_ingestion_function(provider_type: str) -> Callable | None:
    """Get the Cartography ingestion function for a provider type."""
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.ingestion_function if config else None


def get_root_node_label(provider_type: str) -> str:
    """Get the root node label for a provider type (e.g., AWSAccount)."""
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.root_node_label if config else "UnknownProviderAccount"


def get_node_uid_field(provider_type: str) -> str:
    """Get the UID field for a provider type (e.g., arn for AWS)."""
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.uid_field if config else "UnknownProviderUID"


def get_provider_resource_label(provider_type: str) -> str:
    """Get the resource label for a provider type (e.g., `_AWSResource`)."""
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.resource_label if config else "_UnknownProviderResource"


# Dynamic Isolation Label Helpers
# --------------------------------


def _normalize_uuid(value: str | UUID) -> str:
    """Strip hyphens from a UUID string for use in Neo4j labels."""
    return str(value).replace("-", "")


def get_tenant_label(tenant_id: str | UUID) -> str:
    """Get the Neo4j label for a tenant (e.g., `_Tenant_019c41ee7df37deca684d839f95619f8`)."""
    return f"{TENANT_LABEL_PREFIX}{_normalize_uuid(tenant_id)}"


def get_provider_label(provider_id: str | UUID) -> str:
    """Get the Neo4j label for a provider (e.g., `_Provider_019c41ee7df37deca684d839f95619f8`)."""
    return f"{PROVIDER_LABEL_PREFIX}{_normalize_uuid(provider_id)}"


def is_dynamic_isolation_label(label: str) -> bool:
    """Check if a label is a dynamic tenant/provider isolation label."""
    return any(label.startswith(prefix) for prefix in DYNAMIC_ISOLATION_PREFIXES)
