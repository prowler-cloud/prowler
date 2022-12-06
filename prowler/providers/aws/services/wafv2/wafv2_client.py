from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

wafv2_client = WAFv2(current_audit_info)
