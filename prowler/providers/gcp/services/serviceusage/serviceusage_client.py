from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.serviceusage.serviceusage_service import (
    ServiceUsage,
)

serviceusage_client = ServiceUsage(global_provider)
