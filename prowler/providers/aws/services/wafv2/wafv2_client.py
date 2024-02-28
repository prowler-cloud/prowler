from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from prowler.providers.common.common import get_global_provider

wafv2_client = WAFv2(get_global_provider())
