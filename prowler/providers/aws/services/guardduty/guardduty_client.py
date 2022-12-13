from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

guardduty_client = GuardDuty(current_audit_info)
