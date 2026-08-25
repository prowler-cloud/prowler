from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.obs.obs_service import OBS

obs_client = OBS(Provider.get_global_provider())
