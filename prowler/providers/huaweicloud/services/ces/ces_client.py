from prowler.providers.huaweicloud.services.ces.ces_service import CES
from prowler.providers.common.provider import Provider

ces_client = CES(Provider.get_global_provider())
