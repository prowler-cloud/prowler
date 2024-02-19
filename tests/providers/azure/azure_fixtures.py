from uuid import uuid4

from azure.identity import DefaultAzureCredential

from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
    Azure_Region_Config,
)

AZURE_SUBSCRIPTION = str(uuid4())

# Azure Identity
IDENTITY_ID = "00000000-0000-0000-0000-000000000000"
IDENTITY_TYPE = "Service Principal"
TENANT_IDS = ["00000000-0000-0000-0000-000000000000"]
DOMAIN = "user.onmicrosoft.com"


# Mocked Azure Audit Info
def set_mocked_azure_audit_info(
    credentials: DefaultAzureCredential = DefaultAzureCredential(),
    identity: Azure_Identity_Info = Azure_Identity_Info(
        identity_id=IDENTITY_ID,
        identity_type=IDENTITY_TYPE,
        tenant_ids=TENANT_IDS,
        domain=DOMAIN,
        subscriptions={AZURE_SUBSCRIPTION: "id_subscription"},
    ),
    audit_config: dict = None,
    azure_region_config: Azure_Region_Config = Azure_Region_Config(),
):
    audit_info = Azure_Audit_Info(
        credentials=credentials,
        identity=identity,
        audit_metadata=None,
        audit_resources=None,
        audit_config=audit_config,
        azure_region_config=azure_region_config,
        locations=None,
    )
    return audit_info
