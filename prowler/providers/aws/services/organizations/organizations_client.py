from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)

organizations_client = Organizations(current_audit_info)
