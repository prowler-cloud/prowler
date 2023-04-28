from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.fms.fms_service import FMS

fms_client = FMS(current_audit_info)
