from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ StorageGateway
class StorageGateway(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.fileshares = []
        self.__threading_call__(self.__list_file_shares__)
        self.__threading_call__(self.__describe_nfs_file_shares__)
        self.__threading_call__(self.__describe_smb_file_shares__)

    def __list_file_shares__(self, regional_client):
        try:
            list_file_share_paginator = regional_client.get_paginator(
                "list_file_shares"
            )
            for page in list_file_share_paginator.paginate():
                for fileshare in page["FileShareInfoList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            fileshare["FileShareARN"], self.audit_resources
                        )
                    ):
                        self.fileshares.append(
                            FileShare(
                                id=fileshare["FileShareId"],
                                arn=fileshare["FileShareARN"],
                                gateway_arn=fileshare["GatewayARN"],
                                region=regional_client.region,
                                fs_type=fileshare["FileShareType"],
                                status=fileshare["FileShareStatus"],
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_nfs_file_shares__(self, regional_client):
        logger.info("StorageGateway - Describe NFS FileShares...")
        try:
            for fileshare in self.fileshares:
                if fileshare.fs_type == "NFS":
                    response = regional_client.describe_nfs_file_shares(
                        FileShareARNList=[fileshare.arn]
                    )
                    fileshare.tags = response["NFSFileShareInfoList"][0].get("Tags", [])
                    fileshare.kms = response["NFSFileShareInfoList"][0]["KMSEncrypted"]
                    fileshare.kms_key = response["NFSFileShareInfoList"][0].get(
                        "KMSKey", ""
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_smb_file_shares__(self, regional_client):
        logger.info("StorageGateway - Describe SMB FileShares...")
        try:
            for fileshare in self.fileshares:
                if fileshare.fs_type == "SMB":
                    response = regional_client.describe_smb_file_shares(
                        FileShareARNList=[fileshare.arn]
                    )
                    fileshare.tags = response["SMBFileShareInfoList"][0].get("Tags", [])
                    fileshare.kms = response["SMBFileShareInfoList"][0]["KMSEncrypted"]
                    fileshare.kms_key = response["SMBFileShareInfoList"][0].get(
                        "KMSKey", ""
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class FileShare(BaseModel):
    id: str
    arn: str
    gateway_arn: str
    region: str
    fs_type: str
    status: str
    kms: Optional[bool]
    kms_key: Optional[str]
    tags: Optional[list] = []
