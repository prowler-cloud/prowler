from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.drs.drs_service import DRS

drs_client = DRS(current_audit_info)
