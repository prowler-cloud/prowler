from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import CloudWatch

cloudwatch_client = CloudWatch(current_audit_info)
