from uuid import uuid4

from azure.identity import DefaultAzureCredential
from mock import MagicMock

from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig

AZURE_SUBSCRIPTION_ID = str(uuid4())
AZURE_SUBSCRIPTION_NAME = "Subscription Name"

# Azure Identity
IDENTITY_ID = "00000000-0000-0000-0000-000000000000"
IDENTITY_TYPE = "Service Principal"
TENANT_IDS = ["00000000-0000-0000-0000-000000000000"]
DOMAIN = "user.onmicrosoft.com"


# Mocked Azure Audit Info
def set_mocked_azure_provider(
    credentials: DefaultAzureCredential = DefaultAzureCredential(),
    identity: AzureIdentityInfo = AzureIdentityInfo(
        identity_id=IDENTITY_ID,
        identity_type=IDENTITY_TYPE,
        tenant_ids=TENANT_IDS,
        domain=DOMAIN,
        subscriptions={AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME},
    ),
    audit_config: dict = None,
    azure_region_config: AzureRegionConfig = AzureRegionConfig(),
    locations: list = None,
) -> AzureProvider:

    provider = MagicMock()
    provider.type = "azure"
    provider.session.credentials = credentials
    provider.identity.locations = locations
    provider.identity = identity
    provider.audit_config = audit_config
    provider.region_config = azure_region_config

    return provider
