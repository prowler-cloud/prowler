from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.serviceusage.serviceusage_service import (
    ServiceUsage,
)

serviceusage_client = ServiceUsage(gcp_audit_info)
