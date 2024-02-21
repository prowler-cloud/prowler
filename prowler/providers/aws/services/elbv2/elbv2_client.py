from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
from prowler.providers.common.common import get_global_provider

elbv2_client = ELBv2(get_global_provider())
