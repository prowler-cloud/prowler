from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.waf.waf_service import WAF

waf_client = WAF(Provider.get_global_provider())
