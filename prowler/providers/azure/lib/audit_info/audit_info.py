from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
    Azure_Region_Config,
)

azure_audit_info = Azure_Audit_Info(
    credentials=None,
    identity=Azure_Identity_Info(),
    audit_resources=None,
    audit_metadata=None,
    audit_config=None,
    azure_region_config=Azure_Region_Config(),
    locations=None,
)
