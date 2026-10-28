from prowler.providers.huaweicloud.services.cce.cce_service import CCE
from prowler.providers.common.provider import Provider

cce_client = CCE(Provider.get_global_provider())
