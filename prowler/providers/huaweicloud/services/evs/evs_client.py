from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.evs.evs_service import EVS

evs_client = EVS(Provider.get_global_provider())
