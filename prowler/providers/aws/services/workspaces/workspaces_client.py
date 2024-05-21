from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpaces
from prowler.providers.common.provider import Provider

workspaces_client = WorkSpaces(Provider.get_global_provider())
