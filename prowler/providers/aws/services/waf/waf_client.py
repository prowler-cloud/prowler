from prowler.providers.aws.services.waf.waf_service import WAF
from prowler.providers.common.common import get_global_provider

waf_client = WAF(get_global_provider())
