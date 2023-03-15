from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.computeengine.computeengine_service import (
    ComputeEngine,
)

computeengine_client = ComputeEngine(gcp_audit_info)
