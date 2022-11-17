from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.workspaces.workspaces_service import WorkSpaces

workspaces_client = WorkSpaces(current_audit_info)
