from prowler.providers.cloudflare.services.waf.waf_service import WAF
from prowler.providers.common.provider import Provider

waf_client = WAF(Provider.get_global_provider())
