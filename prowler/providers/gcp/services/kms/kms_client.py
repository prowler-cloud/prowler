from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.services.kms.kms_service import KMS

kms_client = KMS(gcp_audit_info)
