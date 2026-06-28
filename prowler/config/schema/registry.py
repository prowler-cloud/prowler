"""Mapping of provider name to its Pydantic schema class.

Kept in its own module so the validator stays free of provider-schema imports
and callers pay the import cost only when they actually need the registry.
"""

from prowler.config.schema.aws import AWSProviderConfig
from prowler.config.schema.azure import AzureProviderConfig
from prowler.config.schema.base import ProviderConfigBase
from prowler.config.schema.cloudflare import CloudflareProviderConfig
from prowler.config.schema.gcp import GCPProviderConfig
from prowler.config.schema.github import GitHubProviderConfig
from prowler.config.schema.kubernetes import KubernetesProviderConfig
from prowler.config.schema.m365 import M365ProviderConfig
from prowler.config.schema.mongodbatlas import MongoDBAtlasProviderConfig
from prowler.config.schema.vercel import VercelProviderConfig

SCHEMAS: dict[str, type[ProviderConfigBase]] = {
    "aws": AWSProviderConfig,
    "azure": AzureProviderConfig,
    "gcp": GCPProviderConfig,
    "kubernetes": KubernetesProviderConfig,
    "m365": M365ProviderConfig,
    "github": GitHubProviderConfig,
    "mongodbatlas": MongoDBAtlasProviderConfig,
    "cloudflare": CloudflareProviderConfig,
    "vercel": VercelProviderConfig,
}
