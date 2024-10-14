from prowler.providers.aws.services.waf.waf_service import WAFRegional
from prowler.providers.common.provider import Provider

wafregional_client = WAFRegional(Provider.get_global_provider())
