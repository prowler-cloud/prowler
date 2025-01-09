import json
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################### EFS
class EFS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.filesystems = {}
        self.__threading_call__(self._describe_file_systems)
        self.__threading_call__(
            self._describe_file_system_policies, self.filesystems.values()
        )
        self.__threading_call__(self._describe_mount_targets, self.filesystems.values())
        self.__threading_call__(self._describe_access_points, self.filesystems.values())

    def _describe_file_systems(self, regional_client):
        logger.info("EFS - Describing file systems...")
        try:
            describe_efs_paginator = regional_client.get_paginator(
                "describe_file_systems"
            )
            for page in describe_efs_paginator.paginate():
                for efs in page["FileSystems"]:
                    efs_id = efs["FileSystemId"]
                    efs_arn = f"arn:{self.audited_partition}:elasticfilesystem:{regional_client.region}:{self.audited_account}:file-system/{efs_id}"
                    if not self.audit_resources or (
                        is_resource_filtered(efs_arn, self.audit_resources)
                    ):
                        self.filesystems[efs_arn] = FileSystem(
                            id=efs_id,
                            arn=efs_arn,
                            region=regional_client.region,
                            availability_zone_id=efs.get("AvailabilityZoneId", ""),
                            number_of_mount_targets=efs["NumberOfMountTargets"],
                            encrypted=efs["Encrypted"],
                            tags=efs.get("Tags"),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_file_system_policies(self, filesystem):
        logger.info("EFS - Describing file system policies...")
        try:
            client = self.regional_clients[filesystem.region]
            try:
                filesystem.backup_policy = client.describe_backup_policy(
                    FileSystemId=filesystem.id
                )["BackupPolicy"]["Status"]
            except ClientError as error:
                if error.response["Error"]["Code"] == "PolicyNotFound":
                    filesystem.backup_policy = "DISABLED"
                    logger.warning(
                        f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            try:
                fs_policy = client.describe_file_system_policy(
                    FileSystemId=filesystem.id
                )
                if "Policy" in fs_policy:
                    filesystem.policy = json.loads(fs_policy["Policy"])
            except ClientError as error:
                if error.response["Error"]["Code"] == "PolicyNotFound":
                    filesystem.policy = {}
                    logger.warning(
                        f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_mount_targets(self, filesystem):
        logger.info("EFS - Describing mount targets...")
        try:
            client = self.regional_clients[filesystem.region]
            describe_mount_target_paginator = client.get_paginator(
                "describe_mount_targets"
            )
            for page in describe_mount_target_paginator.paginate(
                FileSystemId=filesystem.id
            ):
                for mount_target in page["MountTargets"]:
                    mount_target_id = mount_target["MountTargetId"]
                    mount_target_arn = f"arn:{self.audited_partition}:elasticfilesystem:{client.region}:{self.audited_account}:mount-target/{mount_target_id}"
                    if not self.audit_resources or (
                        is_resource_filtered(mount_target_arn, self.audit_resources)
                    ):
                        self.filesystems[filesystem.arn].mount_targets.append(
                            MountTarget(
                                id=mount_target_id,
                                file_system_id=mount_target["FileSystemId"],
                                subnet_id=mount_target["SubnetId"],
                            )
                        )
        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_access_points(self, filesystem):
        logger.info("EFS - Describing access points...")
        try:
            client = self.regional_clients[filesystem.region]
            describe_access_point_paginator = client.get_paginator(
                "describe_access_points"
            )
            for page in describe_access_point_paginator.paginate(
                FileSystemId=filesystem.id
            ):
                for access_point in page["AccessPoints"]:
                    access_point_id = access_point["AccessPointId"]
                    access_point_arn = access_point["AccessPointArn"]
                    if not self.audit_resources or (
                        is_resource_filtered(access_point_arn, self.audit_resources)
                    ):
                        self.filesystems[filesystem.arn].access_points.append(
                            AccessPoint(
                                id=access_point_id,
                                file_system_id=access_point["FileSystemId"],
                                root_directory_path=access_point["RootDirectory"][
                                    "Path"
                                ],
                                posix_user=access_point.get("PosixUser", {}),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class MountTarget(BaseModel):
    id: str
    file_system_id: str
    subnet_id: str


class AccessPoint(BaseModel):
    id: str
    file_system_id: str
    root_directory_path: str
    posix_user: dict = {}


class FileSystem(BaseModel):
    id: str
    arn: str
    region: str
    policy: Optional[dict] = {}
    backup_policy: Optional[str] = "DISABLED"
    encrypted: bool
    availability_zone_id: Optional[str]
    number_of_mount_targets: int
    mount_targets: list[MountTarget] = []
    access_points: list[AccessPoint] = []
    tags: Optional[list] = []
