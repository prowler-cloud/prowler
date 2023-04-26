from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.inspector2.inspector2_service import Inspector2

inspector2_client = Inspector2(current_audit_info)
