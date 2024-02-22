from prowler.providers.aws.services.acm.acm_service import ACM
from prowler.providers.common.common import get_global_provider

acm_client = ACM(get_global_provider())
