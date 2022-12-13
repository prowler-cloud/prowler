from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.kms.kms_service import KMS

kms_client = KMS(current_audit_info)
