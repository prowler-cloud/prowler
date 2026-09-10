from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.vpc.vpc_service import VPC

vpc_client = VPC(Provider.get_global_provider())
