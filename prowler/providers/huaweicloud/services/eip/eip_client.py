from prowler.providers.huaweicloud.services.eip.eip_service import EIP
from prowler.providers.common.provider import Provider

eip_client = EIP(Provider.get_global_provider())
