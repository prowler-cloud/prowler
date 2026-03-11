from dataclasses import dataclass
from typing import Callable

from config.env import env

from tasks.jobs.attack_paths import aws


# Batch size for Neo4j operations
BATCH_SIZE = env.int("ATTACK_PATHS_BATCH_SIZE", 1000)

# Neo4j internal labels (Prowler-specific, not provider-specific)
# - `ProwlerFinding`: Label for finding nodes created by Prowler and linked to cloud resources
# - `_ProviderResource`: Added to ALL synced nodes for provider isolation and drop/query ops
# - `Internet`: Singleton node representing external internet access for exposed-resource queries
PROWLER_FINDING_LABEL = "ProwlerFinding"
PROVIDER_RESOURCE_LABEL = "_ProviderResource"
INTERNET_NODE_LABEL = "Internet"

# Phase 1 dual-write: deprecated label kept for drop_subgraph and infrastructure queries
# Remove in Phase 2 once all nodes use the private label exclusively
DEPRECATED_PROVIDER_RESOURCE_LABEL = "ProviderResource"


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration for a cloud provider's Attack Paths integration."""

    name: str
    root_node_label: str  # e.g., "AWSAccount"
    uid_field: str  # e.g., "arn"
    # Label for resources connected to the account node, enabling indexed finding lookups.
    resource_label: str  # e.g., "_AWSResource"
    deprecated_resource_label: str  # e.g., "AWSResource"
    ingestion_function: Callable


# Provider Configurations
# -----------------------

AWS_CONFIG = ProviderConfig(
    name="aws",
    root_node_label="AWSAccount",
    uid_field="arn",
    resource_label="_AWSResource",
    deprecated_resource_label="AWSResource",
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
    DEPRECATED_PROVIDER_RESOURCE_LABEL,
    # Add all provider-specific resource labels
    *[config.resource_label for config in PROVIDER_CONFIGS.values()],
    *[config.deprecated_resource_label for config in PROVIDER_CONFIGS.values()],
]

# Provider isolation properties
PROVIDER_ISOLATION_PROPERTIES: list[str] = [
    "_provider_id",
    "_provider_element_id",
    "provider_id",
    "provider_element_id",
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


def get_deprecated_provider_resource_label(provider_type: str) -> str:
    """Get the deprecated resource label for a provider type (e.g., `AWSResource`)."""
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.deprecated_resource_label if config else "UnknownProviderResource"
