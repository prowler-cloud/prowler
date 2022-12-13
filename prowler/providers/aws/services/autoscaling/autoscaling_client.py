from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.autoscaling.autoscaling_service import AutoScaling

autoscaling_client = AutoScaling(current_audit_info)
