from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from prowler.providers.common.provider import Provider

wafv2_client = WAFv2(Provider.get_global_provider())
