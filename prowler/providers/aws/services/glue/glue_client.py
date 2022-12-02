from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.glue.glue_service import Glue

glue_client = Glue(current_audit_info)
