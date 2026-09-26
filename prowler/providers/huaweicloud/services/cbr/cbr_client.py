from prowler.providers.huaweicloud.services.cbr.cbr_service import CBR
from prowler.providers.common.provider import Provider

cbr_client = CBR(Provider.get_global_provider())
