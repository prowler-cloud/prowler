from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.serviceusage.serviceusage_service import (
    ServiceUsage,
)

serviceusage_client = ServiceUsage(Provider.get_global_provider())
