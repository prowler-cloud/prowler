from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.emr.emr_service import EMR

emr_client = EMR(current_audit_info)
