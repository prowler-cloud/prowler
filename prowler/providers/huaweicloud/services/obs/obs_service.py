from typing import List, Optional, Tuple

from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException
from huaweicloudsdkobs.v1 import (
    GetBucketAclRequest,
    GetBucketMetadataRequest,
    GetBucketNotificationRequest,
    GetBucketObjectLockRequest,
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
                    object_lock_enabled = self._get_bucket_object_lock(
                        bucket_client, bucket_name
                    )
                    az_redundancy, cors_allow_origin = self._get_bucket_metadata(
                        bucket_client, bucket_name
                    )
                    event_notification_enabled = self._get_bucket_notification(
                        bucket_client, bucket_name
                    )
                    acl_everyone_permissions = (
                        self._get_bucket_acl_everyone_permissions(
                            bucket_client, bucket_name
                        )
                    )

                    self.buckets.append(
                        Bucket(
                            name=bucket_name,
                            region=bucket_region,
                            is_public=is_public,
                            acl=acl,
                            object_lock_enabled=object_lock_enabled,
                            az_redundancy=az_redundancy,
                            cors_allow_origin=cors_allow_origin,
                            event_notification_enabled=event_notification_enabled,
                            acl_everyone_permissions=acl_everyone_permissions,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_bucket_object_lock(
        self, bucket_client, bucket_name: str
    ) -> Optional[bool]:
        """Return whether bucket-level WORM (Object Lock) is enabled, or None on error."""
        try:
            response = self._call_with_retries(
                bucket_client.get_bucket_object_lock,
                GetBucketObjectLockRequest(bucket_name=bucket_name),
            )
            config = getattr(response, "object_lock_configuration", None)
            return getattr(config, "object_lock_enabled", None) == "Enabled"
        except ClientRequestException as error:
            if getattr(error, "status_code", None) == 404:
                return False
            logger.error(
                f"OBS - Object lock check failed for bucket {bucket_name}: {error}"
            )
            return None
        except Exception as error:
            logger.error(
                f"OBS - Object lock check failed for bucket {bucket_name}: {error}"
            )
            return None

    def _get_bucket_metadata(
        self, bucket_client, bucket_name: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Return (az_redundancy, cors_allow_origin) for a bucket, or (None, None) on error."""
        try:
            response = self._call_with_retries(
                bucket_client.get_bucket_metadata,
                GetBucketMetadataRequest(bucket_name=bucket_name),
            )
            raw_az = getattr(response, "x_obs_az_redundancy", None)
            raw_cors = getattr(response, "access_control_allow_origin", None)
            az_redundancy = raw_az if isinstance(raw_az, str) else ""
            cors_allow_origin = raw_cors if isinstance(raw_cors, str) else ""
            return az_redundancy, cors_allow_origin
        except Exception as error:
            logger.error(
                f"OBS - Metadata check failed for bucket {bucket_name}: {error}"
            )
            return None, None

    def _get_bucket_notification(
        self, bucket_client, bucket_name: str
    ) -> Optional[bool]:
        """Return whether bucket event notifications are configured, or None on error."""
        try:
            response = self._call_with_retries(
                bucket_client.get_bucket_notification,
                GetBucketNotificationRequest(bucket_name=bucket_name),
            )
            config = getattr(response, "notification_configuration", None)
            if not config:
                return False
            topics = getattr(config, "topic_configuration", None) or []
            functions = getattr(config, "function_stage_configuration", None) or []
            return bool(topics or functions)
        except ClientRequestException as error:
            if getattr(error, "status_code", None) == 404:
                return False
            logger.error(
                f"OBS - Notification check failed for bucket {bucket_name}: {error}"
            )
            return None
        except Exception as error:
            logger.error(
                f"OBS - Notification check failed for bucket {bucket_name}: {error}"
            )
            return None

    def _get_bucket_acl_everyone_permissions(
        self, bucket_client, bucket_name: str
    ) -> Optional[List[str]]:
        """Return ACL permissions granted to Everyone, or None on error."""
        try:
            response = self._call_with_retries(
                bucket_client.get_bucket_acl,
                GetBucketAclRequest(bucket_name=bucket_name),
            )
            acl = getattr(response, "access_control_list", None)
            grants = getattr(acl, "grant", None) or []
            permissions = []
            for grant in grants:
                grantee = getattr(grant, "grantee", None)
                if getattr(grantee, "canned", None) == "Everyone":
                    permission = getattr(grant, "permission", None)
                    if permission:
                        permissions.append(permission)
            return permissions
        except Exception as error:
            logger.error(f"OBS - ACL check failed for bucket {bucket_name}: {error}")
            return None


class Bucket(HuaweiCloudBaseModel):
    """OBS Bucket model."""

    name: str
    region: str = ""
    is_public: bool = False
    acl: str = ""
    object_lock_enabled: Optional[bool] = None
    az_redundancy: Optional[str] = None
    cors_allow_origin: Optional[str] = None
    event_notification_enabled: Optional[bool] = None
    acl_everyone_permissions: Optional[List[str]] = None
