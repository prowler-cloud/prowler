from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.waf.waf_service import WAF

waf_client = WAF(current_audit_info)
