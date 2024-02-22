from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.serviceusage.serviceusage_service import (
    ServiceUsage,
)

serviceusage_client = ServiceUsage(get_global_provider())
