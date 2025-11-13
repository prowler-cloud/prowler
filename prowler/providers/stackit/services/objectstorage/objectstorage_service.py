import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider


class ObjectStorageService:
    """
    StackIT Object Storage Service class to handle bucket operations.

    This service uses boto3 with S3-compatible endpoints to access
    StackIT Object Storage, which is S3-compatible.
    """

    # StackIT Object Storage endpoint
    STACKIT_S3_ENDPOINT = "https://object.storage.eu01.onstackit.cloud"

    def __init__(self, provider: StackitProvider):
        """
        Initialize the Object Storage service.

        Args:
            provider: The StackIT provider instance
        """
        self.provider = provider
        self.project_id = provider.identity.project_id

        # Get Object Storage credentials from session
        self.objectstorage_access_key = provider.session.get("objectstorage_access_key")
        self.objectstorage_secret_key = provider.session.get("objectstorage_secret_key")

        # Initialize buckets list
        self.buckets: list[Bucket] = []

        # Check if Object Storage credentials are available
        if not self.objectstorage_access_key or not self.objectstorage_secret_key:
            logger.info(
                "Object Storage credentials not provided. Skipping Object Storage bucket discovery. "
                "To scan Object Storage, generate credentials in STACKIT Portal and provide them via "
                "--stackit-objectstorage-access-key and --stackit-objectstorage-secret-key."
            )
            return

        # Fetch all buckets and their configurations
        self._list_buckets()

    def _get_s3_client(self):
        """
        Get or create the S3-compatible client for StackIT Object Storage.

        Returns:
            boto3 S3 client configured for StackIT endpoints, or None if credentials are missing
        """
        # Check if credentials are available
        if not self.objectstorage_access_key or not self.objectstorage_secret_key:
            logger.warning(
                "Object Storage credentials not available. Cannot create S3 client."
            )
            return None

        try:
            # Create S3 client with StackIT Object Storage credentials
            s3_client = boto3.client(
                "s3",
                endpoint_url=self.STACKIT_S3_ENDPOINT,
                aws_access_key_id=self.objectstorage_access_key,
                aws_secret_access_key=self.objectstorage_secret_key,
                config=Config(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                ),
            )
            return s3_client
        except Exception as e:
            logger.error(
                f"Error initializing StackIT Object Storage S3 client: {e}"
            )
            return None

    def _list_buckets(self):
        """
        List all buckets in the StackIT project and fetch their configurations.

        This method populates the self.buckets list with Bucket objects
        containing information about each bucket including encryption status.
        """
        try:
            s3_client = self._get_s3_client()
            if not s3_client:
                logger.warning(
                    "Cannot list buckets: S3 client not available"
                )
                return

            # List all buckets using S3 API
            try:
                response = s3_client.list_buckets()
                buckets_list = response.get("Buckets", [])
            except EndpointConnectionError as e:
                logger.error(
                    f"Cannot connect to StackIT Object Storage endpoint: {e}. "
                    f"Please verify the endpoint {self.STACKIT_S3_ENDPOINT} is correct "
                    "and accessible."
                )
                return
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                if error_code == "InvalidAccessKeyId":
                    logger.error(
                        "Invalid credentials. Please verify your API token and project ID."
                    )
                elif error_code == "SignatureDoesNotMatch":
                    logger.error(
                        "Authentication failed. The API token may be invalid or expired."
                    )
                else:
                    logger.error(
                        f"Error listing buckets: {e.response.get('Error', {}).get('Message', str(e))}"
                    )
                return
            except Exception as e:
                logger.error(f"Unexpected error listing buckets: {e}")
                return

            # Process each bucket
            for bucket_data in buckets_list:
                try:
                    bucket_name = bucket_data.get("Name", "")
                    creation_date = bucket_data.get("CreationDate", None)

                    # Get bucket location/region
                    region = self._get_bucket_location(s3_client, bucket_name)

                    # Check bucket encryption
                    encryption_enabled = self._check_bucket_encryption(
                        s3_client, bucket_name
                    )

                    # Create Bucket object
                    bucket = Bucket(
                        id=bucket_name,
                        name=bucket_name,
                        project_id=self.project_id,
                        region=region,
                        encryption_enabled=encryption_enabled,
                    )
                    self.buckets.append(bucket)

                except Exception as e:
                    logger.error(
                        f"Error processing bucket {bucket_data.get('Name', 'unknown')}: {e}"
                    )
                    continue

            logger.info(f"Successfully listed {len(self.buckets)} buckets")

        except Exception as e:
            logger.error(f"Error listing StackIT Object Storage buckets: {e}")

    def _get_bucket_location(self, s3_client, bucket_name: str) -> str:
        """
        Get the location/region of a bucket.

        Args:
            s3_client: The boto3 S3 client
            bucket_name: The name of the bucket

        Returns:
            str: The bucket location/region
        """
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint", "eu01")
            # If LocationConstraint is None, it means the default region
            return location if location else "eu01"
        except ClientError as e:
            logger.debug(
                f"Cannot determine location for bucket {bucket_name}: {e}"
            )
            return "eu01"
        except Exception as e:
            logger.debug(
                f"Error getting location for bucket {bucket_name}: {e}"
            )
            return "eu01"

    def _check_bucket_encryption(self, s3_client, bucket_name: str) -> bool:
        """
        Check if a bucket has encryption enabled.

        Args:
            s3_client: The boto3 S3 client
            bucket_name: The name of the bucket to check

        Returns:
            bool: True if encryption is enabled, False otherwise
        """
        try:
            # Try to get bucket encryption configuration
            response = s3_client.get_bucket_encryption(Bucket=bucket_name)

            # If we get a response, encryption is enabled
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            if rules:
                # Check if there's at least one encryption rule
                for rule in rules:
                    sse_algorithm = (
                        rule.get("ApplyServerSideEncryptionByDefault", {}).get(
                            "SSEAlgorithm"
                        )
                    )
                    if sse_algorithm:
                        logger.debug(
                            f"Bucket {bucket_name} has encryption enabled with algorithm: {sse_algorithm}"
                        )
                        return True
            return False

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                # No encryption configuration = encryption is not enabled
                logger.debug(
                    f"Bucket {bucket_name} does not have encryption enabled"
                )
                return False
            else:
                # Other error - log and assume not encrypted
                logger.debug(
                    f"Error checking encryption for bucket {bucket_name}: {error_code}"
                )
                return False
        except Exception as e:
            logger.debug(
                f"Cannot determine encryption status for bucket {bucket_name}: {e}"
            )
            return False


class Bucket(BaseModel):
    """
    Represents a StackIT Object Storage bucket.

    Attributes:
        id: The unique identifier of the bucket (same as name for S3)
        name: The name of the bucket
        project_id: The StackIT project ID containing the bucket
        region: The region where the bucket is located
        encryption_enabled: Whether encryption is enabled for the bucket
    """

    id: str
    name: str
    project_id: str
    region: str = "eu01"
    encryption_enabled: bool = False
