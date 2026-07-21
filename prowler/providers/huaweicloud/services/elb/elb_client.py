from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.elb.elb_service import ELB

elb_client = ELB(Provider.get_global_provider())
