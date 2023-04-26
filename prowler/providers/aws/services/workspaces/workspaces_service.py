import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ WorkSpaces
class WorkSpaces:
    def __init__(self, audit_info):
        self.service = "workspaces"
        self.session = audit_info.audit_session
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.workspaces = []
        self.__threading_call__(self.__describe_workspaces__)
        self.__describe_tags__()

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_workspaces__(self, regional_client):
        logger.info("WorkSpaces - describing workspaces...")
        try:
            describe_workspaces_paginator = regional_client.get_paginator(
                "describe_workspaces"
            )
            for page in describe_workspaces_paginator.paginate():
                for workspace in page["Workspaces"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            workspace["WorkspaceId"], self.audit_resources
                        )
                    ):
                        workspace_to_append = WorkSpace(
                            id=workspace["WorkspaceId"], region=regional_client.region, subnet_id=workspace["SubnetId"]
                        )
                        if (
                            "UserVolumeEncryptionEnabled" in workspace
                            and workspace["UserVolumeEncryptionEnabled"]
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

    def __describe_tags__(self):
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
    arn: str = ""
    region: str
    user_volume_encryption_enabled: bool = None
    root_volume_encryption_enabled: bool = None
    subnet_id: str
    tags: Optional[list] = []
