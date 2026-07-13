from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class OBS(HuaweiCloudService):
    """
    OBS (Object Storage Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud OBS service
    to retrieve buckets and their configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.buckets: List[Bucket] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_buckets()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.buckets = [
            Bucket(
                name="mock-public-encrypted-bucket", region=region,
                is_encrypted=True, is_public=True, acl="public",
            ),
            Bucket(
                name="mock-private-unencrypted-bucket", region=region,
                is_encrypted=False, is_public=False, acl="private",
            ),
            Bucket(
                name="mock-private-encrypted-bucket", region=region,
                is_encrypted=True, is_public=False, acl="private",
            ),
        ]

    def _list_buckets(self):
        """List all OBS buckets."""
        if not self.client:
            return

        region = self.region
        client = self.client
        logger.info(f"OBS - Listing Buckets in {region}...")

        try:

            response = client.listBuckets()

            if response and response.body and response.body.buckets:
                for bucket_data in response.body.buckets:
                    bucket_name = getattr(bucket_data, "name", "")
                    bucket_region = getattr(bucket_data, "location", region)

                    is_encrypted = False
                    is_public = False
                    acl = ""

                    try:
                        acl_response = client.getBucketAcl(bucket_name)
                        if acl_response and acl_response.body:
                            grants = getattr(acl_response.body, "grants", [])
                            for grant in grants:
                                grantee = getattr(grant, "grantee", None)
                                if grantee:
                                    grantee_id = getattr(grantee, "id", "")
                                    if grantee_id == "Everyone" or grantee_id == "*":
                                        is_public = True
                                        acl = "public"
                    except Exception as acl_error:
                        logger.error(
                            f"OBS - ACL check failed for bucket {bucket_name}: {acl_error}"
                        )

                    try:
                        encryption_response = client.getBucketEncryption(bucket_name)
                        if encryption_response and encryption_response.body:
                            is_encrypted = True
                    except Exception:
                        pass

                    self.buckets.append(
                        Bucket(
                            name=bucket_name,
                            region=bucket_region,
                            is_encrypted=is_encrypted,
                            is_public=is_public,
                            acl=acl,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Bucket(BaseModel):
    """OBS Bucket model."""

    name: str
    region: str = ""
    is_encrypted: bool = False
    is_public: bool = False
    acl: str = ""
