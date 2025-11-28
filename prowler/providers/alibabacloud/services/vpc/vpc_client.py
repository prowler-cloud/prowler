from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC
from prowler.providers.common.provider import Provider

vpc_client = VPC(Provider.get_global_provider())
