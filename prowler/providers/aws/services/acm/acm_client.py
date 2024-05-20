from prowler.providers.aws.services.acm.acm_service import ACM
from prowler.providers.common.provider import Provider

acm_client = ACM(Provider.get_global_provider())
