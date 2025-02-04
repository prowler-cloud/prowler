from azure.identity import DefaultAzureCredential
from mock import MagicMock

from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider
from prowler.providers.microsoft365.models import (
    Microsoft365IdentityInfo,
    Microsoft365RegionConfig,
)

# Azure Identity
IDENTITY_ID = "00000000-0000-0000-0000-000000000000"
IDENTITY_TYPE = "Application"
TENANT_ID = "00000000-0000-0000-0000-000000000000"
CLIENT_ID = "00000000-0000-0000-0000-000000000000"
CLIENT_SECRET = "00000000-0000-0000-0000-000000000000"
DOMAIN = "user.onmicrosoft.com"
LOCATION = "global"


# Mocked Azure Audit Info
def set_mocked_microsoft365_provider(
    credentials: DefaultAzureCredential = DefaultAzureCredential(),
    identity: Microsoft365IdentityInfo = Microsoft365IdentityInfo(
        identity_id=IDENTITY_ID,
        identity_type=IDENTITY_TYPE,
        tenant_id=TENANT_ID,
        tenant_domain=DOMAIN,
    ),
    audit_config: dict = None,
    azure_region_config: Microsoft365RegionConfig = Microsoft365RegionConfig(),
) -> Microsoft365Provider:
    provider = MagicMock()
    provider.type = "microsoft365"
    provider.session.credentials = credentials
    provider.identity = identity
    provider.audit_config = audit_config
    provider.region_config = azure_region_config

    return provider
