from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    TrustedAdvisor,
)
from prowler.providers.common.common import get_global_provider

trustedadvisor_client = TrustedAdvisor(get_global_provider())
