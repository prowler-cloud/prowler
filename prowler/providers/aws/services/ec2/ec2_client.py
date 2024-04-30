from prowler.providers.aws.services.ec2.ec2_service import EC2
from prowler.providers.common.provider import Provider

ec2_client = EC2(Provider.get_global_provider())
