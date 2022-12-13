from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.glue.glue_service import Glue

glue_client = Glue(current_audit_info)
