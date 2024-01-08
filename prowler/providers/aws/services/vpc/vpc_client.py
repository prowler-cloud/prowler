from prowler.providers.aws.services.vpc.vpc_service import VPC
from prowler.providers.common.common import get_global_provider

vpc_client = VPC(get_global_provider())
