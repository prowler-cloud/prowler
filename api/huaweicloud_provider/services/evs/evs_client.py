from prowler.providers.huaweicloud.services.evs.evs_service import EVS
from prowler.providers.common.provider import Provider

evs_client = EVS(Provider.get_global_provider())
