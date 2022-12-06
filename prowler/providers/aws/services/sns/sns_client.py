from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.sns.sns_service import SNS

sns_client = SNS(current_audit_info)
