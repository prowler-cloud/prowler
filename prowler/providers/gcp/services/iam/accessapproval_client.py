from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.iam.iam_service import AccessApproval

accessapproval_client = AccessApproval(gcp_audit_info)
