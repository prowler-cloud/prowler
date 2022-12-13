from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.glacier.glacier_service import Glacier

glacier_client = Glacier(current_audit_info)
