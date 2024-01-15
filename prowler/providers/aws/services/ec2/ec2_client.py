from prowler.providers.aws.services.ec2.ec2_service import EC2
from prowler.providers.common.common import get_global_provider

ec2_client = EC2(get_global_provider())
