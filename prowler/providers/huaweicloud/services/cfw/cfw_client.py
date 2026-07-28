from prowler.providers.huaweicloud.services.cfw.cfw_service import CFW
from prowler.providers.common.provider import Provider

cfw_client = CFW(Provider.get_global_provider())
