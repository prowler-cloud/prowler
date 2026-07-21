from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class KMS(HuaweiCloudService):
    """
    KMS (Key Management Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud KMS service
    to retrieve KMS keys and their rotation status.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.keys: List[KMSKey] = []

        self.__threading_call__(self._list_keys)

    def _list_keys(self, regional_client):
        """List all KMS keys across regions."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"KMS - Listing Keys in {region}...")

        try:
            from huaweicloudsdkkms.v2 import ListKeysRequest, ListKeysRequestBody

            request = ListKeysRequest(body=ListKeysRequestBody(limit="100"))
            response = self._call_with_retries(regional_client.list_keys, request)

            if response and response.key_details:
                for key_data in response.key_details:
                    key_id = getattr(key_data, "key_id", "")
                    is_rotation_enabled = False
                    rotation_period = ""

                    try:
                        from huaweicloudsdkkms.v2 import (
                            OperateKeyRequestBody,
                            ShowKeyRotationStatusRequest,
                        )

                        rotation_request = ShowKeyRotationStatusRequest(
                            body=OperateKeyRequestBody(key_id=key_id)
                        )
                        rotation_response = self._call_with_retries(
                            regional_client.show_key_rotation_status, rotation_request
                        )
                        if rotation_response:
                            is_rotation_enabled = getattr(
                                rotation_response, "key_rotation_enabled", False
                            )
                            rotation_period = getattr(
                                rotation_response, "rotation_interval", ""
                            )
                    except Exception as rotation_error:
                        logger.error(
                            f"{region} -- KMS rotation check failed for key {key_id}: {rotation_error}"
                        )

                    self.keys.append(
                        KMSKey(
                            id=key_id,
                            domain_id=getattr(key_data, "domain_id", ""),
                            alias=getattr(key_data, "key_alias", ""),
                            state=getattr(key_data, "key_state", ""),
                            is_rotation_enabled=is_rotation_enabled,
                            rotation_period=rotation_period,
                            region=region,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class KMSKey(BaseModel):
    """KMS Key model."""

    id: str
    domain_id: str = ""
    alias: str = ""
    state: str = ""
    is_rotation_enabled: bool = False
    rotation_period: str = ""
    region: str = ""
