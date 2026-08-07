from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.nat.nat_service import NAT

nat_client = NAT(Provider.get_global_provider())
