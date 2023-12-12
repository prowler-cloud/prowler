from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    AzureIdentityInfo,
    AzureRegionConfig,
)

azure_audit_info = Azure_Audit_Info(
    credentials=None,
    identity=AzureIdentityInfo(),
    audit_resources=None,
    audit_metadata=None,
    audit_config=None,
    azure_region_config=AzureRegionConfig(),
)
