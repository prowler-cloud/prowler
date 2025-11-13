from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider


class ObjectStorageService:
    """
    StackIT Object Storage Service class to handle bucket operations.

    This service uses the StackIT Python SDK to access Object Storage
    using API token authentication.
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

    def _get_stackit_client(self):
        """
        Get or create the StackIT Object Storage client using the SDK.

        Returns:
            StackIT Object Storage client configured with API token
        """
        try:
            # Import the StackIT SDK
            from stackit.core.configuration import Configuration
            from stackit.objectstorage import ApiClient, DefaultApi

            # Create configuration with API token
            # Note: project_id is passed to API methods, not to Configuration
            config = Configuration(
                service_account_token=self.api_token,
            )

            # Initialize the API client and Object Storage API
            api_client = ApiClient(config)
            client = DefaultApi(api_client)
            return client

        except ImportError as e:
            logger.error(
                f"StackIT SDK not available: {e}. "
                "Please ensure stackit-core and stackit-objectstorage are installed."
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
            client = self._get_stackit_client()
            if not client:
                logger.warning(
                    "Cannot list buckets: StackIT Object Storage client not available"
                )
                return

            # List all buckets using the SDK
            try:
                # Call the list buckets API
                response = client.list_buckets(project_id=self.project_id)

                # Extract buckets from response
                if hasattr(response, "buckets"):
                    buckets_list = response.buckets
                elif isinstance(response, dict):
                    buckets_list = response.get("buckets", [])
                elif isinstance(response, list):
                    buckets_list = response
                else:
                    logger.warning(
                        f"Unexpected response type from list_buckets: {type(response)}"
                    )
                    buckets_list = []

            except Exception as e:
                logger.error(f"Error listing buckets via SDK: {e}")
                return

            # Process each bucket
            for bucket_data in buckets_list:
                try:
                    # Extract bucket information
                    if hasattr(bucket_data, "name"):
                        bucket_name = bucket_data.name
                        bucket_id = getattr(bucket_data, "id", bucket_name)
                        region = getattr(bucket_data, "region", "eu01")
                    elif isinstance(bucket_data, dict):
                        bucket_name = bucket_data.get("name", "")
                        bucket_id = bucket_data.get("id", bucket_name)
                        region = bucket_data.get("region", "eu01")
                    else:
                        logger.warning(
                            f"Unexpected bucket data type: {type(bucket_data)}"
                        )
                        continue

                    # Check bucket encryption
                    encryption_enabled = self._check_bucket_encryption(
                        client, bucket_name
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
                    logger.error(f"Error processing bucket: {e}")
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
            # Get bucket encryption configuration via SDK
            try:
                encryption_config = client.get_bucket_encryption(
                    project_id=self.project_id, bucket_name=bucket_name
                )

                # Check if encryption is enabled based on response structure
                if hasattr(encryption_config, "enabled"):
                    return encryption_config.enabled
                elif hasattr(encryption_config, "algorithm"):
                    # If an algorithm is set, encryption is enabled
                    return True
                elif isinstance(encryption_config, dict):
                    return (
                        encryption_config.get("enabled", False)
                        or encryption_config.get("algorithm") is not None
                    )
                else:
                    # If we got a valid response object, assume encryption is enabled
                    return True

            except AttributeError as e:
                # Method might not exist in current SDK version
                logger.debug(
                    f"Cannot determine encryption status for bucket {bucket_name}: {e}"
                )
                return False
            except Exception as e:
                # Check if it's a "not configured" error
                error_str = str(e).lower()
                if (
                    "not found" in error_str
                    or "not configured" in error_str
                    or "does not exist" in error_str
                ):
                    logger.debug(
                        f"Bucket {bucket_name} does not have encryption configured"
                    )
                    return False
                else:
                    logger.debug(
                        f"Error checking encryption for bucket {bucket_name}: {e}"
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
        id: The unique identifier of the bucket
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
