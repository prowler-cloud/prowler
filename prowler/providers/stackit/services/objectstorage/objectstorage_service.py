from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider


class ObjectStorageService:
    """
    StackIT Object Storage Service class to handle bucket operations.

    This service uses the StackIT Object Storage SDK to list buckets
    and retrieve their encryption configurations.
    """

    def __init__(self, provider: StackitProvider):
        """
        Initialize the Object Storage service.

        Args:
            provider: The StackIT provider instance
        """
        self.provider = provider
        self.project_id = provider.identity.project_id
        self.api_token = provider.session.get("api_token")

        # Initialize buckets list
        self.buckets: list[Bucket] = []

        # Fetch all buckets and their configurations
        self._list_buckets()

    def _get_client(self):
        """
        Get or create the StackIT Object Storage client.

        Returns:
            A configured StackIT Object Storage client
        """
        try:
            # Import the StackIT SDK
            # Note: The exact import and initialization may need adjustment
            # based on the actual StackIT SDK structure
            from stackit.objectstorage import ObjectStorageClient

            # Initialize the client with authentication
            client = ObjectStorageClient(
                project_id=self.project_id,
                api_token=self.api_token,
            )
            return client
        except ImportError as e:
            logger.error(
                f"StackIT Object Storage SDK not available: {e}. "
                "Please install it with: pip install stackit-objectstorage"
            )
            return None
        except Exception as e:
            logger.error(f"Error initializing StackIT Object Storage client: {e}")
            return None

    def _list_buckets(self):
        """
        List all buckets in the StackIT project and fetch their configurations.

        This method populates the self.buckets list with Bucket objects
        containing information about each bucket including encryption status.
        """
        try:
            client = self._get_client()
            if not client:
                logger.warning(
                    "Cannot list buckets: StackIT Object Storage client not available"
                )
                return

            # List all buckets
            # Note: The exact API method may need adjustment based on the actual SDK
            try:
                buckets_response = client.list_buckets()
                buckets_list = (
                    buckets_response.get("buckets", [])
                    if isinstance(buckets_response, dict)
                    else buckets_response
                )
            except AttributeError:
                # If the SDK structure is different, try alternative methods
                logger.warning(
                    "StackIT Object Storage SDK structure may have changed. "
                    "Please verify the SDK documentation."
                )
                buckets_list = []

            # Process each bucket
            for bucket_data in buckets_list:
                try:
                    # Extract bucket information
                    bucket_name = (
                        bucket_data.get("name")
                        if isinstance(bucket_data, dict)
                        else getattr(bucket_data, "name", "")
                    )
                    bucket_id = (
                        bucket_data.get("id", bucket_name)
                        if isinstance(bucket_data, dict)
                        else getattr(bucket_data, "id", bucket_name)
                    )

                    # Get bucket encryption configuration
                    encryption_enabled = self._check_bucket_encryption(
                        client, bucket_name
                    )

                    # Get bucket region/location
                    region = (
                        bucket_data.get("region", "")
                        if isinstance(bucket_data, dict)
                        else getattr(bucket_data, "region", "")
                    )

                    # Create Bucket object
                    bucket = Bucket(
                        id=bucket_id,
                        name=bucket_name,
                        project_id=self.project_id,
                        region=region,
                        encryption_enabled=encryption_enabled,
                    )
                    self.buckets.append(bucket)

                except Exception as e:
                    logger.error(f"Error processing bucket data: {e}")
                    continue

            logger.info(f"Successfully listed {len(self.buckets)} buckets")

        except Exception as e:
            logger.error(f"Error listing StackIT Object Storage buckets: {e}")

    def _check_bucket_encryption(self, client, bucket_name: str) -> bool:
        """
        Check if a bucket has encryption enabled.

        Args:
            client: The StackIT Object Storage client
            bucket_name: The name of the bucket to check

        Returns:
            bool: True if encryption is enabled, False otherwise
        """
        try:
            # Get bucket encryption configuration
            # Note: The exact API method may need adjustment based on the actual SDK
            try:
                encryption_config = client.get_bucket_encryption(bucket_name)

                # Check if encryption is enabled
                # The exact structure depends on the SDK response
                if isinstance(encryption_config, dict):
                    # Check for common encryption indicators
                    return (
                        encryption_config.get("enabled", False)
                        or encryption_config.get("encrypted", False)
                        or "encryption" in encryption_config
                    )
                else:
                    # If it's an object, check for attributes
                    return getattr(encryption_config, "enabled", False) or getattr(
                        encryption_config, "encrypted", False
                    )

            except AttributeError:
                # Method might not exist or SDK structure is different
                logger.debug(
                    f"Cannot determine encryption status for bucket {bucket_name}: "
                    "SDK method not available"
                )
                return False

        except Exception as e:
            # If we can't determine encryption status, log and assume not encrypted
            logger.debug(
                f"Cannot determine encryption status for bucket {bucket_name}: {e}"
            )
            return False


class Bucket(BaseModel):
    """
    Represents a StackIT Object Storage bucket.

    Attributes:
        id: The unique identifier of the bucket
        name: The name of the bucket
        project_id: The StackIT project ID containing the bucket
        region: The region where the bucket is located
        encryption_enabled: Whether encryption is enabled for the bucket
    """

    id: str
    name: str
    project_id: str
    region: str = ""
    encryption_enabled: bool = False
