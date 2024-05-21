from prowler.providers.aws.services.elb.elb_service import ELB
from prowler.providers.common.provider import Provider

elb_client = ELB(Provider.get_global_provider())
