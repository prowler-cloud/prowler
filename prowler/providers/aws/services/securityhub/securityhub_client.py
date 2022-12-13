from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.securityhub.securityhub_service import SecurityHub

securityhub_client = SecurityHub(current_audit_info)
