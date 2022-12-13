from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.efs.efs_service import EFS

efs_client = EFS(current_audit_info)
