from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.rds.rds_service import RDS

rds_client = RDS(current_audit_info)
