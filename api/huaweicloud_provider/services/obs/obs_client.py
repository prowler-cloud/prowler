from prowler.providers.huaweicloud.services.obs.obs_service import OBS
from prowler.providers.common.provider import Provider

obs_client = OBS(Provider.get_global_provider())
