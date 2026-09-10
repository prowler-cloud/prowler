from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.cts.cts_service import CTS

cts_client = CTS(Provider.get_global_provider())
