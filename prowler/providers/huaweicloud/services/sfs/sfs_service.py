from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class SFS(HuaweiCloudService):
    """
    SFS (Scalable File Service) Turbo service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud SFS Turbo service
    to retrieve file systems (shares).
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.shares: List[SFSShare] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_shares()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.shares = [
            SFSShare(
                share_id="sfs-share-001",
                name="share-encrypted",
                crypt_key_id="kms-key-001",
                region=region,
            ),
            SFSShare(
                share_id="sfs-share-002",
                name="share-unencrypted",
                crypt_key_id="",
                region=region,
            ),
        ]

    def _list_shares(self):
        """List all SFS Turbo shares across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"SFS - Listing Shares in {region}...")

            try:
                from huaweicloudsdksfsturbo.v1 import ListSharesRequest

                request = ListSharesRequest()
                response = self._call_with_retries(client.list_shares, request)

                if response and response.shares:
                    for share in response.shares:
                        share_id = getattr(share, "id", "")
                        name = getattr(share, "name", "")
                        crypt_key_id = getattr(share, "crypt_key_id", "") or ""

                        self.shares.append(
                            SFSShare(
                                share_id=share_id,
                                name=name,
                                crypt_key_id=crypt_key_id,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class SFSShare(BaseModel):
    """SFS Turbo share model."""

    share_id: str
    name: str = ""
    crypt_key_id: str = ""
    region: str = ""
