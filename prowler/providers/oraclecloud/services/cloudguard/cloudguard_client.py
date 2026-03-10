from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.cloudguard.cloudguard_service import (
    CloudGuard,
)

cloudguard_client = CloudGuard(Provider.get_global_provider())
