from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.gke.gke_service import GKE

gke_client = GKE(gcp_audit_info)
