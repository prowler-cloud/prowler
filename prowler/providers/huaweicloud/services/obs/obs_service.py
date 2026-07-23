from typing import List

from huaweicloudsdkobs.v1 import (
    GetBucketPolicyPublicStatusRequest,
    GetBucketPublicStatusRequest,
    ListBucketsRequest,
)

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class OBS(HuaweiCloudService):
    """
    OBS (Object Storage Service) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud OBS service
    to retrieve buckets and their configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.buckets: List[Bucket] = []
        self._region_clients = {}

        self._list_buckets()

    def _client_for_region(self, region):
        """Return an OBS client bound to the bucket's region (cached).

        Bucket-scoped operations must target the bucket's own region endpoint,
        so a client is created per bucket region and reused. Falls back to the
        default-region client if one cannot be created.
        """
        if region not in self._region_clients:
            try:
                self._region_clients[region] = self.session.client("obs", region)
            except Exception as error:
                logger.error(
                    f"OBS - Could not create client for region {region}: {error}"
                )
                self._region_clients[region] = None
        return self._region_clients[region] or self.client

    def _list_buckets(self):
        """List all OBS buckets."""
        if not self.client:
            return

        region = self.region
        logger.info(f"OBS - Listing Buckets in {region}...")

        try:
            response = self._call_with_retries(
                self.client.list_buckets, ListBucketsRequest()
            )

            if response and response.buckets and response.buckets.bucket:
                for bucket_data in response.buckets.bucket:
                    bucket_name = getattr(bucket_data, "name", "") or ""
                    bucket_region = getattr(bucket_data, "location", None) or region
                    bucket_client = self._client_for_region(bucket_region)

                    is_public = False
                    acl = ""

                    try:
                        public_status = self._call_with_retries(
                            bucket_client.get_bucket_public_status,
                            GetBucketPublicStatusRequest(bucket_name=bucket_name),
                        )
                        if public_status and public_status.is_public:
                            is_public = True
                    except Exception as public_error:
                        logger.error(
                            f"OBS - Public status check failed for bucket {bucket_name}: {public_error}"
                        )

                    try:
                        policy_status = self._call_with_retries(
                            bucket_client.get_bucket_policy_public_status,
                            GetBucketPolicyPublicStatusRequest(bucket_name=bucket_name),
                        )
                        if policy_status and policy_status.is_public:
                            is_public = True
                    except Exception as policy_error:
                        logger.error(
                            f"OBS - Policy public status check failed for bucket {bucket_name}: {policy_error}"
                        )

                    acl = "public" if is_public else "private"

                    self.buckets.append(
                        Bucket(
                            name=bucket_name,
                            region=bucket_region,
                            is_public=is_public,
                            acl=acl,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Bucket(HuaweiCloudBaseModel):
    """OBS Bucket model."""

    name: str
    region: str = ""
    is_public: bool = False
    acl: str = ""
