import json
import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## KMS
class KMS:
    def __init__(self, audit_info):
        self.service = "kms"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.keys = []
        self.__threading_call__(self.__list_keys__)
        if self.keys:
            self.__describe_key__()
            self.__get_key_rotation_status__()
            self.__get_key_policy__()

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

    def __list_keys__(self, regional_client):
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

    def __describe_key__(self):
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

    def __get_key_rotation_status__(self):
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

    def __get_key_policy__(self):
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
