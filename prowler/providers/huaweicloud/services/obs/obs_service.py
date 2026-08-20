from typing import List, Optional

from huaweicloudsdkobs.v1 import (
    GetBucketPolicyPublicStatusRequest,
    GetBucketPublicStatusRequest,
)

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel

LIST_BUCKETS_PAGE_SIZE = 1000
NO_ENCRYPTION_CONFIGURATION = "NoSuchEncryptionConfiguration"


class OBS(HuaweiCloudService):
    """Retrieve Huawei Cloud OBS buckets and their security configuration."""

    def __init__(self, provider):
        """Initialize OBS clients and discover buckets."""
        super().__init__(__class__.__name__, provider, global_service=True)

        self.buckets: List[Bucket] = []
        self._region_clients = {}
        self._data_clients = {}

        self._list_buckets()

    def _client_for_region(self, region):
        """Return a cached OBS management client for a bucket region."""
        if region not in self._region_clients:
            try:
                self._region_clients[region] = self.session.client("obs", region)
            except Exception as error:
                logger.error(
                    f"OBS - Could not create management client for region {region}: {error}"
                )
                self._region_clients[region] = None
        return self._region_clients[region] or self.client

    def _data_client_for_region(self, region):
        """Return a cached OBS data-plane client for a bucket region."""
        if region not in self._data_clients:
            self._data_clients[region] = self.session.client("obs_data", region)
        return self._data_clients[region]

    def _get_public_access(self, client, bucket_name):
        """Return True, False, or None when public access cannot be determined."""
        statuses = []
        operations = (
            (
                client.get_bucket_public_status,
                GetBucketPublicStatusRequest(bucket_name=bucket_name),
                "Public status",
            ),
            (
                client.get_bucket_policy_public_status,
                GetBucketPolicyPublicStatusRequest(bucket_name=bucket_name),
                "Policy public status",
            ),
        )

        for operation, request, label in operations:
            try:
                response = self._call_with_retries(operation, request)
                statuses.append(bool(response and response.is_public))
            except Exception as error:
                logger.error(
                    f"OBS - {label} check failed for bucket {bucket_name}: {error}"
                )

        if any(statuses):
            return True
        if len(statuses) == len(operations):
            return False
        return None

    def _get_encryption(self, client, bucket_name):
        """Return the bucket encryption state, type, key, and discovery error."""
        try:
            response = self._call_with_retries(client.getBucketEncryption, bucket_name)
        except Exception as error:
            logger.error(
                f"OBS - Encryption check failed for bucket {bucket_name}: {error}"
            )
            return None, "", "", str(error)

        if response and response.status < 300:
            encryption = getattr(response.body, "encryption", "") or ""
            key = getattr(response.body, "key", "") or ""
            if encryption:
                return True, encryption, key, ""
            return None, "", "", "Empty encryption configuration response"

        error_code = getattr(response, "errorCode", "") or ""
        error_message = getattr(response, "errorMessage", "") or ""
        if error_code == NO_ENCRYPTION_CONFIGURATION:
            return False, "", "", ""

        status = getattr(response, "status", "unknown")
        error = ": ".join(value for value in (error_code, error_message) if value)
        return None, "", "", error or f"HTTP {status}"

    def _list_buckets(self):
        """List all OBS buckets, following the data-plane pagination markers."""
        region = self.region
        logger.info(f"OBS - Listing buckets from {region}...")

        try:
            list_client = self._data_client_for_region(region)
            marker = None

            while True:
                response = self._call_with_retries(
                    list_client.listBuckets,
                    isQueryLocation=True,
                    maxKeys=LIST_BUCKETS_PAGE_SIZE,
                    marker=marker,
                )
                if (
                    marker is None
                    and response
                    and response.status == 400
                    and getattr(response, "errorCode", "") == "InvalidRequest"
                ):
                    logger.warning(
                        "OBS - Endpoint rejected bucket-list pagination; "
                        "retrying without pagination parameters"
                    )
                    response = self._call_with_retries(
                        list_client.listBuckets,
                        isQueryLocation=True,
                    )
                if not response or response.status >= 300:
                    error_code = getattr(response, "errorCode", "") or ""
                    error_message = getattr(response, "errorMessage", "") or ""
                    logger.error(
                        f"OBS - Could not list buckets: {error_code}: {error_message}"
                    )
                    return

                body = response.body
                for bucket_data in getattr(body, "buckets", None) or []:
                    bucket_name = getattr(bucket_data, "name", "") or ""
                    bucket_region = getattr(bucket_data, "location", None) or region
                    management_client = self._client_for_region(bucket_region)
                    data_client = self._data_client_for_region(bucket_region)
                    is_public = self._get_public_access(management_client, bucket_name)
                    (
                        is_encrypted,
                        encryption,
                        encryption_key,
                        encryption_error,
                    ) = self._get_encryption(data_client, bucket_name)

                    self.buckets.append(
                        Bucket(
                            id=bucket_name,
                            arn=f"huaweicloud:obs:{bucket_region}:{self.audited_account}:bucket/{bucket_name}",
                            name=bucket_name,
                            region=bucket_region,
                            is_public=is_public,
                            acl=(
                                "public"
                                if is_public is True
                                else "private" if is_public is False else "unknown"
                            ),
                            is_encrypted=is_encrypted,
                            encryption=encryption,
                            encryption_key=encryption_key,
                            encryption_error=encryption_error,
                        )
                    )

                next_marker = getattr(body, "nextMarker", None)
                if next_marker:
                    marker = next_marker
                    continue
                if getattr(body, "isTruncated", False):
                    logger.error(
                        "OBS - Bucket list response was truncated without a next marker"
                    )
                return

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Bucket(HuaweiCloudBaseModel):
    """OBS bucket and its discovered security configuration."""

    id: str = ""
    arn: str = ""
    name: str
    region: str = ""
    is_public: Optional[bool] = None
    acl: str = "unknown"
    is_encrypted: Optional[bool] = None
    encryption: str = ""
    encryption_key: str = ""
    encryption_error: str = ""
