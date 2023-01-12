import threading
from dataclasses import dataclass

from botocore.client import ClientError

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################### EFS
class EFS:
    def __init__(self, audit_info):
        self.service = "efs"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.filesystems = []
        self.__threading_call__(self.__describe_file_systems__)
        self.__describe_file_system_policies__()

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

    def __describe_file_systems__(self, regional_client):
        logger.info("EFS - Describing file systems...")
        try:
            describe_efs_paginator = regional_client.get_paginator(
                "describe_file_systems"
            )
            for page in describe_efs_paginator.paginate():
                for efs in page["FileSystems"]:
                    self.filesystems.append(
                        FileSystem(
                            id=efs["FileSystemId"],
                            region=regional_client.region,
                            policy=None,
                            backup_policy=None,
                            encrypted=efs["Encrypted"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_file_system_policies__(self):
        logger.info("EFS - Describing file system policies...")
        try:
            for filesystem in self.filesystems:
                for region, client in self.regional_clients.items():
                    if filesystem.region == region:
                        try:
                            filesystem.backup_policy = client.describe_backup_policy(
                                FileSystemId=filesystem.id
                            )["BackupPolicy"]["Status"]
                        except ClientError as e:
                            if e.response["Error"]["Code"] == "PolicyNotFound":
                                filesystem.backup_policy = "DISABLED"
                        try:
                            fs_policy = client.describe_file_system_policy(
                                FileSystemId=filesystem.id
                            )
                            if "Policy" in fs_policy:
                                filesystem.policy = fs_policy["Policy"]
                        except ClientError as e:
                            if e.response["Error"]["Code"] == "PolicyNotFound":
                                filesystem.policy = {}
        except Exception as error:
            logger.error(
                f"{client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class FileSystem:
    id: str
    region: str
    policy: dict
    backup_policy: str
    encrypted: bool

    def __init__(
        self,
        id,
        region,
        policy,
        backup_policy,
        encrypted,
    ):
        self.id = id
        self.region = region
        self.policy = policy
        self.backup_policy = backup_policy
        self.encrypted = encrypted
