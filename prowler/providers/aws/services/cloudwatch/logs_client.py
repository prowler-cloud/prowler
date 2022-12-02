from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.cloudwatch.cloudwatch_service import Logs

logs_client = Logs(current_audit_info)
