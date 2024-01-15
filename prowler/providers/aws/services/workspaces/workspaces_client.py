from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpaces
from prowler.providers.common.common import get_global_provider

workspaces_client = WorkSpaces(get_global_provider())
