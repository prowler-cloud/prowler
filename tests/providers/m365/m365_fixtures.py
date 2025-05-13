from azure.identity import DefaultAzureCredential
from mock import MagicMock

from prowler.providers.m365.m365_provider import M365Provider
from prowler.providers.m365.models import (
    M365Credentials,
    M365IdentityInfo,
    M365RegionConfig,
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
def set_mocked_m365_provider(
    session_credentials: DefaultAzureCredential = DefaultAzureCredential(),
    credentials: M365Credentials = M365Credentials(
        user="user@email.com", passwd="111111aa111111aaa1111"
    ),
    identity: M365IdentityInfo = M365IdentityInfo(
        identity_id=IDENTITY_ID,
        identity_type=IDENTITY_TYPE,
        tenant_id=TENANT_ID,
        tenant_domain=DOMAIN,
        user="user@email.com",
    ),
    audit_config: dict = None,
    azure_region_config: M365RegionConfig = M365RegionConfig(),
) -> M365Provider:
    provider = MagicMock()
    provider.type = "m365"
    provider.session.credentials = session_credentials
    provider.credentials = credentials
    provider.identity = identity
    provider.audit_config = audit_config
    provider.region_config = azure_region_config

    return provider
