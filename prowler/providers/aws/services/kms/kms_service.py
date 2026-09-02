import json
from typing import Optional

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class KMS(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.keys = []
        self.keys_scan_errors = {}
        self.__threading_call__(self._list_keys)
        if self.keys:
            self._describe_key()
            self._get_key_rotation_status()
            self._get_key_policy()
            self._list_resource_tags()
            self.__threading_call__(self._list_aliases)

    def _list_keys(self, regional_client):
        logger.info("KMS - Listing Keys...")
        region_keys = []
        try:
            list_keys_paginator = regional_client.get_paginator("list_keys")
            for page in list_keys_paginator.paginate():
                for key in page["Keys"]:
                    if not self.audit_resources or (
                        is_resource_filtered(key["KeyArn"], self.audit_resources)
                    ):
                        region_keys.append(
                            Key(
                                id=key["KeyId"],
                                arn=key["KeyArn"],
                                region=regional_client.region,
                            )
                        )
            self.keys.extend(region_keys)
        except ClientError as error:
            self.keys_scan_errors[regional_client.region] = error.response["Error"].get(
                "Code", error.__class__.__name__
            )
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
        except Exception as error:
            self.keys_scan_errors[regional_client.region] = error.__class__.__name__
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def _describe_key(self):
        """Retrieve metadata for each discovered KMS key.

        Records the error code or exception type on keys whose metadata cannot
        be retrieved so checks can report incomplete evidence.
        """
        logger.info("KMS - Describing Key...")
        for key in self.keys:
            try:
                regional_client = self.regional_clients[key.region]
                metadata = regional_client.describe_key(KeyId=key.id)["KeyMetadata"]
                state = metadata["KeyState"]
                origin = metadata["Origin"]
                manager = metadata["KeyManager"]
                spec = metadata["CustomerMasterKeySpec"]
                multi_region = metadata.get("MultiRegion", False)
                description = metadata.get("Description", "")

                key.state = state
                key.origin = origin
                key.manager = manager
                key.spec = spec
                key.multi_region = multi_region
                key.description = description
                key.detail_retrieved = True
            except ClientError as error:
                key.detail_fetch_error = error.response["Error"].get(
                    "Code", error.__class__.__name__
                )
                logger.error(
                    f"{key.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                )
            except Exception as error:
                key.detail_fetch_error = error.__class__.__name__
                logger.error(
                    f"{key.region} -- {error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
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
    # False when DescribeKey failed. Checks that require key metadata must
    # report MANUAL instead of treating absent fields as configuration values.
    detail_retrieved: bool = False
    detail_fetch_error: Optional[str] = None
    spec: Optional[str]
    region: str
    multi_region: Optional[bool]
    description: Optional[str] = ""
    aliases: Optional[list] = []
    tags: Optional[list] = []
