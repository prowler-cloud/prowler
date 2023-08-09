from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)

azure_audit_info = Azure_Audit_Info(
    credentials=None,
    identity=Azure_Identity_Info(),
    audit_resources=None,
    audit_metadata=None,
    audit_config=None,
)
