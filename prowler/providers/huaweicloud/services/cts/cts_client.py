from prowler.providers.huaweicloud.services.cts.cts_service import CTS
from prowler.providers.common.provider import Provider

cts_client = CTS(Provider.get_global_provider())
