"""OCI Object Storage Service Module."""

from datetime import datetime
from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class ObjectStorage(OCIService):
    """OCI Object Storage Service class to retrieve buckets and their configurations."""

    def __init__(self, provider):
        """
        Initialize the Object Storage service.

        Args:
            provider: The OCI provider instance
        """
        super().__init__("objectstorage", provider)
        self.buckets = []
        self.namespace = self.__get_namespace__()
        if self.namespace:
            self.__threading_call_by_region_and_compartment__(self.__list_buckets__)

    def __get_client__(self, region):
        """
        Get the Object Storage client for a region.

        Args:
            region: Region key

        Returns:
            Object Storage client instance
        """
        return self._create_oci_client(
            oci.object_storage.ObjectStorageClient, config_overrides={"region": region}
        )

    def __get_namespace__(self):
        """Get the Object Storage namespace for the tenancy."""
        try:
            # Use any regional client to get the namespace
            client = self.__get_client__(list(self.regional_clients.keys())[0])
            namespace = client.get_namespace().data
            logger.info(f"Object Storage - Namespace: {namespace}")
            return namespace
        except Exception as error:
            logger.error(
                f"Error getting Object Storage namespace: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def __list_buckets__(self, region, compartment):
        """
        List all Object Storage buckets in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            # Extract region key from OCIRegion object
            region_key = region.key if hasattr(region, "key") else str(region)
            os_client = self.__get_client__(region_key)

            logger.info(
                f"Object Storage - Listing Buckets in {region_key} - {compartment.name}..."
            )

            buckets_data = oci.pagination.list_call_get_all_results(
                os_client.list_buckets,
                namespace_name=self.namespace,
                compartment_id=compartment.id,
            ).data

            for bucket in buckets_data:
                # Get bucket details for encryption and versioning info
                try:
                    bucket_details = os_client.get_bucket(
                        namespace_name=self.namespace, bucket_name=bucket.name
                    ).data

                    # Get public access type
                    public_access_type = getattr(
                        bucket_details, "public_access_type", "NoPublicAccess"
                    )

                    # Get versioning status
                    versioning = getattr(bucket_details, "versioning", "Disabled")

                    # Get encryption details
                    kms_key_id = getattr(bucket_details, "kms_key_id", None)

                    # Create a unique ID for the bucket using namespace/bucket_name
                    bucket_id = f"{self.namespace}/{bucket.name}"

                    self.buckets.append(
                        Bucket(
                            id=bucket_id,
                            name=bucket.name,
                            compartment_id=compartment.id,
                            namespace=self.namespace,
                            time_created=bucket.time_created,
                            public_access_type=public_access_type,
                            versioning=versioning,
                            kms_key_id=kms_key_id,
                            region=region_key,
                        )
                    )
                except Exception as detail_error:
                    logger.error(
                        f"Error getting bucket details for {bucket.name}: {detail_error.__class__.__name__}[{detail_error.__traceback__.tb_lineno}]: {detail_error}"
                    )
                    continue

        except Exception as error:
            logger.error(
                f"{region_key} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class Bucket(BaseModel):
    """OCI Object Storage Bucket model."""

    id: str  # Using namespace/bucket_name as ID
    name: str
    compartment_id: str
    namespace: str
    time_created: datetime
    public_access_type: str
    versioning: str
    kms_key_id: Optional[str]
    region: str
