from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.ec2.ec2_service import EC2

ec2_client = EC2(current_audit_info)
