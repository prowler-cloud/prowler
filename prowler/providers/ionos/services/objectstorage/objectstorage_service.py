from typing import Dict, Optional

import boto3
from botocore.config import Config
from ionoscloud.api import UserManagementApi, UserS3KeysApi

from prowler.lib.logger import logger
from prowler.providers.ionos.lib.service import IonosService


class IonosObjectStorage(IonosService):
    """
    IonosObjectStorage is the class for handling object storage resources in IONOS Cloud.
    """

    REGIONS: Dict[str, str] = {
        "eu-south-2": "https://s3-eu-south-2.ionoscloud.com",
        "eu-central-2": "https://s3-eu-central-2.ionoscloud.com",
        "de": "https://s3-eu-central-1.ionoscloud.com",
    }

    def __init__(self, provider):
        """
        Initialize IonosObjectStorage class.

        Args:
            provider: IonosProvider instance with authenticated credentials
        """
        logger.info("Initializing IONOS Object Storage service")
        super().__init__(provider)
        self.service = "objectstorage"
        self.s3_client = UserS3KeysApi(self.session)
        self.access_key: Optional[str] = None
        self.secret_key: Optional[str] = None
        self.users_client = UserManagementApi(self.session)
        self.bucket_regions: Dict[str, str] = {}

        self.user_uuid = self.__get_user_uuid__()
        self.__get_credentials__()

        if not self.access_key or not self.secret_key or not self.user_uuid:
            logger.warning(
                "Missing credentials (access key, secret key, or user UUID). "
                "S3 client initialization skipped."
            )
            self.client = None
            return

        self.client = boto3.client(
            "s3",
            endpoint_url="https://s3-eu-south-2.ionoscloud.com",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=Config(signature_version="s3v4"),
        )

        self.region_clients: Dict[str, boto3.client] = {}
        self._initialize_region_clients()
        self.__get_objectstorage_resources__()

    def _initialize_region_clients(self) -> None:
        """Initialize S3 clients for each region."""
        for region, endpoint in self.REGIONS.items():
            self.region_clients[region] = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
            )

    def __get_objectstorage_resources__(self) -> None:
        """Get all object storage resources from IONOS Cloud."""
        if not self.client:
            logger.warning(
                "S3 client is not initialized. Skipping object storage resource retrieval."
            )
            return

        logger.info("Getting IONOS object storage resources...")
        self.__get_buckets__()

    def __get_buckets__(self) -> None:
        """Get all buckets from IONOS Object Storage."""
        if not self.client:
            logger.warning("S3 client is not initialized. Skipping bucket retrieval.")
            return

        logger.info("Getting buckets from IONOS Object Storage")
        try:
            buckets = [
                bucket["Name"] for bucket in self.client.list_buckets()["Buckets"]
            ]

            for bucket in buckets:
                for region_code in self.REGIONS:
                    try:
                        self.region_clients[region_code].head_bucket(Bucket=bucket)
                        self.bucket_regions[bucket] = region_code
                        break
                    except RecursionError:
                        continue
                else:
                    logger.warning("Could not determine region for bucket: %s", bucket)

        except Exception as error:
            logger.error(
                "Object Storage -- %s[%s]: %s",
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )

    def get_all_buckets(self) -> Dict[str, str]:
        """Get all buckets."""
        return self.bucket_regions

    def get_region_client(self, region: str) -> Optional[boto3.client]:
        """
        Get the S3 client for a specific region.

        Args:
            region: Region name (e.g., 'eu-south-2')

        Returns:
            boto3.client: S3 client for the specified region or None if not found
        """
        return self.region_clients.get(region)

    def get_bucket_by_name(self, bucket_name: str) -> Optional[dict]:
        """
        Get bucket details by bucket name.

        Args:
            bucket_name: Name of the bucket to get

        Returns:
            dict: Bucket details or None if not found
        """
        for bucket in self.client.list_buckets()["Buckets"]:
            if bucket["Name"] == bucket_name:
                return bucket
        return None

    def get_bucket_location(self, bucket_name: str) -> Optional[str]:
        """
        Get the location of a specific bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            str: Location of the bucket or None if not found
        """
        s3_client = self.get_region_client(self.bucket_regions.get(bucket_name, ""))
        if not s3_client:
            logger.warning("Region client is not available for bucket: %s", bucket_name)
            return None

        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint")
            return location if location else "None"
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                bucket_name,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_bucket_acl(self, bucket_name: str) -> Optional[dict]:
        """
        Get the ACL of a specific bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            dict: Cleaned ACL configuration or None if not found
        """
        s3_client = self.get_region_client(self.bucket_regions.get(bucket_name, ""))
        if not s3_client:
            logger.warning("Region client is not available for bucket: %s", bucket_name)
            return None

        try:
            response = s3_client.get_bucket_acl(Bucket=bucket_name)
            cleaned_acl = {
                "Owner": response.get("Owner", {}),
                "Grants": response.get("Grants", []),
            }
            return cleaned_acl
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                bucket_name,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_bucket_encryption(self, bucket_name: str) -> Optional[dict]:
        """
        Get the encryption configuration of a specific bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            dict: Encryption configuration or None if not found
        """
        if not self.client:
            return None

        try:
            return self.client.get_bucket_encryption(Bucket=bucket_name)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                bucket_name,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def get_bucket_versioning(self, bucket_name: str) -> Optional[dict]:
        """
        Get the versioning configuration of a specific bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            dict: Versioning configuration or None if not found
        """
        if not self.client:
            return None

        try:
            return self.client.get_bucket_versioning(Bucket=bucket_name)
        except Exception as error:
            logger.error(
                "%s -- %s[%s]: %s",
                bucket_name,
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
            return None

    def __get_credentials__(self) -> None:
        """Fetch access and secret keys for the user."""
        try:
            s3_keys = self.s3_client.um_users_s3keys_get(self.user_uuid, depth=1)
            if s3_keys.items:
                self.access_key = s3_keys.items[0].id
                self.secret_key = s3_keys.items[0].properties.secret_key
        except Exception as error:
            logger.error(
                "Error accessing S3 keys -- %s[%s]: %s",
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )

    def __get_user_uuid__(self) -> Optional[str]:
        """Return the UUID of the current user."""
        try:
            users = self.users_client.um_users_get(depth=1)
            for user in users.items:
                if user.properties.email == self.identity.username:
                    return user.id
        except Exception as error:
            logger.error(
                "Error accessing user UUID -- %s[%s]: %s",
                error.__class__.__name__,
                error.__traceback__.tb_lineno,
                error,
            )
        return None
