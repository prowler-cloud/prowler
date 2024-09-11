from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ WorkSpaces
class WorkSpaces(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.workspaces = []
        self.__threading_call__(self._describe_workspaces)
        self._describe_tags()

    def _describe_workspaces(self, regional_client):
        logger.info("WorkSpaces - describing workspaces...")
        try:
            describe_workspaces_paginator = regional_client.get_paginator(
                "describe_workspaces"
            )
            for page in describe_workspaces_paginator.paginate():
                for workspace in page["Workspaces"]:
                    arn = f"arn:{self.audited_partition}:workspaces:{regional_client.region}:{self.audited_account}:workspace/{workspace['WorkspaceId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        workspace_to_append = WorkSpace(
                            arn=arn,
                            id=workspace.get("WorkspaceId"),
                            region=regional_client.region,
                            subnet_id=workspace.get("SubnetId"),
                        )
                        if (
                            "UserVolumeEncryptionEnabled" in workspace
                            and workspace.get("UserVolumeEncryptionEnabled")
                        ):
                            workspace_to_append.user_volume_encryption_enabled = True
                        if (
                            "RootVolumeEncryptionEnabled" in workspace
                            and workspace["RootVolumeEncryptionEnabled"]
                        ):
                            workspace_to_append.root_volume_encryption_enabled = True
                        self.workspaces.append(workspace_to_append)

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_tags(self):
        logger.info("Workspaces - List Tags...")
        try:
            for workspace in self.workspaces:
                regional_client = self.regional_clients[workspace.region]
                response = regional_client.describe_tags(ResourceId=workspace.id)[
                    "TagList"
                ]
                workspace.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class WorkSpace(BaseModel):
    id: str
    arn: str
    region: str
    user_volume_encryption_enabled: bool = None
    root_volume_encryption_enabled: bool = None
    subnet_id: str = None
    tags: Optional[list] = []
