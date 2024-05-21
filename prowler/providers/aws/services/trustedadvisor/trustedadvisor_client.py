from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    TrustedAdvisor,
)
from prowler.providers.common.provider import Provider

trustedadvisor_client = TrustedAdvisor(Provider.get_global_provider())
