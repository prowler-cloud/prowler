from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.compute.compute_service import Compute

compute_client = Compute(gcp_audit_info)
