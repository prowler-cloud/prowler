import json
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## KMS
class KMS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.keys = []
        self.__threading_call__(self._list_keys)
        if self.keys:
            self._describe_key()
            self._get_key_rotation_status()
            self._get_key_policy()
            self._list_resource_tags()

    def _list_keys(self, regional_client):
        logger.info("KMS - Listing Keys...")
        try:
            list_keys_paginator = regional_client.get_paginator("list_keys")
            for page in list_keys_paginator.paginate():
                for key in page["Keys"]:
                    if not self.audit_resources or (
                        is_resource_filtered(key["KeyArn"], self.audit_resources)
                    ):
                        self.keys.append(
                            Key(
                                id=key["KeyId"],
                                arn=key["KeyArn"],
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_key(self):
        logger.info("KMS - Describing Key...")
        try:
            for key in self.keys:
                regional_client = self.regional_clients[key.region]
                response = regional_client.describe_key(KeyId=key.id)
                key.state = response["KeyMetadata"]["KeyState"]
                key.origin = response["KeyMetadata"]["Origin"]
                key.manager = response["KeyMetadata"]["KeyManager"]
                key.spec = response["KeyMetadata"]["CustomerMasterKeySpec"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _get_key_rotation_status(self):
        logger.info("KMS - Get Key Rotation Status...")
        try:
            for key in self.keys:
                if (
                    key.origin
                    and key.manager
                    and "EXTERNAL" not in key.origin
                    and "AWS" not in key.manager
                ):
                    regional_client = self.regional_clients[key.region]
                    key.rotation_enabled = regional_client.get_key_rotation_status(
                        KeyId=key.id
                    )["KeyRotationEnabled"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _get_key_policy(self):
        logger.info("KMS - Get Key Policy...")
        try:
            for key in self.keys:
                if (
                    key.manager and key.manager == "CUSTOMER"
                ):  # only customer KMS have policies
                    regional_client = self.regional_clients[key.region]
                    key.policy = json.loads(
                        regional_client.get_key_policy(
                            KeyId=key.id, PolicyName="default"
                        )["Policy"]
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_resource_tags(self):
        logger.info("KMS - List Tags...")
        for key in self.keys:
            if (
                key.manager and key.manager == "CUSTOMER"
            ):  # only check customer KMS keys
                try:
                    regional_client = self.regional_clients[key.region]
                    response = regional_client.list_resource_tags(
                        KeyId=key.id,
                    )["Tags"]
                    key.tags = response
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


class Key(BaseModel):
    id: str
    arn: str
    state: Optional[str]
    origin: Optional[str]
    manager: Optional[str]
    rotation_enabled: Optional[bool]
    policy: Optional[dict]
    spec: Optional[str]
    region: str
    tags: Optional[list] = []
