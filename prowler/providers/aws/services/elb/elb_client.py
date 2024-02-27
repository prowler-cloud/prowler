from prowler.providers.aws.services.elb.elb_service import ELB
from prowler.providers.common.common import get_global_provider

elb_client = ELB(get_global_provider())
