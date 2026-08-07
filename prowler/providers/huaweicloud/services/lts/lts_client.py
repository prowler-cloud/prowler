from prowler.providers.huaweicloud.services.lts.lts_service import LTS
from prowler.providers.common.provider import Provider

lts_client = LTS(Provider.get_global_provider())
