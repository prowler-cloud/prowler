from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.dlm.dlm_service import Dlm

dlm_client = DLM(current_audit_info)
