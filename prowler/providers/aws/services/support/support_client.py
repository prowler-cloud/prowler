from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.support.support_service import Support

support_client = Support(current_audit_info)
