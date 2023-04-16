from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    SSMIncidents,
)

ssmincidents_client = SSMIncidents(current_audit_info)
