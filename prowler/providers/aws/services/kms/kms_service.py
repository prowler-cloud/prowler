import json
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


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
            self.__threading_call__(self._list_aliases)

    def _list_keys(self, regional_client):
        logger.info("KMS - Listing Keys...")
        try:
            list_keys_paginator = regional_client.get_paginator("list_keys")
            for page in list_keys_paginator.paginate():
                for key in page["Keys"]:
                    try:
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
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_key(self):
        logger.info("KMS - Describing Key...")
        try:
            for key in self.keys:
                regional_client = self.regional_clients[key.region]
                try:
                    response = regional_client.describe_key(KeyId=key.id)
                    key.state = response["KeyMetadata"]["KeyState"]
                    key.origin = response["KeyMetadata"]["Origin"]
                    key.manager = response["KeyMetadata"]["KeyManager"]
                    key.spec = response["KeyMetadata"]["CustomerMasterKeySpec"]
                    key.multi_region = response["KeyMetadata"]["MultiRegion"]
                    key.description = response["KeyMetadata"].get("Description", "")
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                    )
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
                    try:
                        key.rotation_enabled = regional_client.get_key_rotation_status(
                            KeyId=key.id
                        )["KeyRotationEnabled"]
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                        )
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
                    try:
                        key.policy = json.loads(
                            regional_client.get_key_policy(
                                KeyId=key.id, PolicyName="default"
                            )["Policy"]
                        )
                    except Exception as error:
                        key.policy_fetch_error = error.__class__.__name__
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_resource_tags(self):
        logger.info("KMS - List Tags...")
        try:
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
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _list_aliases(self, regional_client):
        logger.info("KMS - Listing Aliases...")
        try:
            aliases_by_key_id = {}
            paginator = regional_client.get_paginator("list_aliases")
            for page in paginator.paginate():
                for alias in page.get("Aliases", []):
                    target_key_id = alias.get("TargetKeyId")
                    if target_key_id:
                        aliases_by_key_id.setdefault(target_key_id, []).append(
                            alias["AliasName"]
                        )
            for key in self.keys:
                if key.region == regional_client.region and key.id in aliases_by_key_id:
                    key.aliases = aliases_by_key_id[key.id]
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
    # Populated by _get_key_policy on API failure. Distinguishes "policy not
    # applicable" (None + no error) from "policy could not be fetched" (None +
    # error class name). Checks that make security assertions from the policy
    # should emit MANUAL when this is set, not silently skip the key.
    policy_fetch_error: Optional[str] = None
    spec: Optional[str]
    region: str
    multi_region: Optional[bool]
    description: Optional[str] = ""
    aliases: Optional[list] = []
    tags: Optional[list] = []
