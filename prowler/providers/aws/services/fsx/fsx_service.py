from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class FSx(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.file_systems = {}
        self.__threading_call__(self._describe_file_systems)

    def _describe_file_systems(self, regional_client):
        logger.info("FSx - Describing file systems...")
        try:
            describe_file_system_paginator = regional_client.get_paginator(
                "describe_file_systems"
            )
            for page in describe_file_system_paginator.paginate():
                for file_system in page["FileSystems"]:
                    file_system_arn = f"arn:{self.audited_partition}:fsx:{regional_client.region}:{self.audited_account}:file-system/{file_system['FileSystemId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(file_system_arn, self.audit_resources)
                    ):
                        type = file_system["FileSystemType"]
                        copy_tags_to_backups_aux = None
                        copy_tags_to_volumes_aux = None
                        if type == "LUSTRE":
                            copy_tags_to_backups_aux = file_system.get(
                                "LustreConfiguration", {}
                            ).get("CopyTagsToBackups", False)
                        elif type == "WINDOWS":
                            copy_tags_to_backups_aux = file_system.get(
                                "WindowsConfiguration", {}
                            ).get("CopyTagsToBackups", False)
                        elif type == "OPENZFS":
                            copy_tags_to_backups_aux = file_system.get(
                                "OpenZFSConfiguration", {}
                            ).get("CopyTagsToBackups", False)
                            copy_tags_to_volumes_aux = file_system.get(
                                "OpenZFSConfiguration", {}
                            ).get("CopyTagsToVolumes", False)

                        self.file_systems[file_system_arn] = FileSystem(
                            id=file_system["FileSystemId"],
                            arn=file_system_arn,
                            type=file_system["FileSystemType"],
                            copy_tags_to_backups=copy_tags_to_backups_aux,
                            copy_tags_to_volumes=copy_tags_to_volumes_aux,
                            subnet_ids=file_system.get("SubnetIds", []),
                            region=regional_client.region,
                            tags=file_system.get("Tags", []),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class FileSystem(BaseModel):
    id: str
    arn: str
    region: str
    type: str
    copy_tags_to_backups: Optional[bool]
    copy_tags_to_volumes: Optional[bool]
    subnet_ids: Optional[list] = []
    tags: Optional[list] = []
