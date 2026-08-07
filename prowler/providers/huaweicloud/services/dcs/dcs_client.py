from prowler.providers.huaweicloud.services.dcs.dcs_service import DCS
from prowler.providers.common.provider import Provider

dcs_client = DCS(Provider.get_global_provider())
