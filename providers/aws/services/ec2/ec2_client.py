from providers.aws.aws_provider import current_audit_info
from providers.aws.services.ec2.ec2_service import EC2

ec2_client = EC2(current_audit_info)
