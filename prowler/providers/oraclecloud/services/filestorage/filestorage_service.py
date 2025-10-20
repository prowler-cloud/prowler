"""OCI Filestorage Service Module."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Filestorage(OCIService):
    """OCI Filestorage Service class."""

    def __init__(self, provider):
        """Initialize the Filestorage service."""
        super().__init__("filestorage", provider)
        self.file_systems = []
        self.__threading_call__(self.__list_file_systems__)

    def __get_client__(self, region):
        """Get the Filestorage client for a region."""
        client_region = self.regional_clients.get(region)
        if client_region:
            return self._create_oci_client(oci.file_storage.FileStorageClient)
        return None

    def __list_file_systems__(self, regional_client):
        """List all file_systems."""
        try:
            client = self.__get_client__(regional_client.region)
            if not client:
                return

            logger.info(
                f"Filestorage - Listing file_systems in {regional_client.region}..."
            )

            for compartment in self.audited_compartments:
                try:
                    # Get availability domains for this compartment
                    identity_client = self._create_oci_client(
                        oci.identity.IdentityClient
                    )
                    availability_domains = identity_client.list_availability_domains(
                        compartment_id=compartment.id
                    ).data

                    # List file systems in each availability domain
                    for ad in availability_domains:
                        items = oci.pagination.list_call_get_all_results(
                            client.list_file_systems,
                            compartment_id=compartment.id,
                            availability_domain=ad.name,
                        ).data

                        for item in items:
                            if item.lifecycle_state not in ["DELETED", "DELETING"]:
                                self.file_systems.append(
                                    FileSystem(
                                        id=item.id,
                                        name=(
                                            item.display_name
                                            if hasattr(item, "display_name")
                                            else item.id
                                        ),
                                        compartment_id=compartment.id,
                                        region=regional_client.region,
                                        lifecycle_state=item.lifecycle_state,
                                        kms_key_id=(
                                            item.kms_key_id
                                            if hasattr(item, "kms_key_id")
                                            else None
                                        ),
                                    )
                                )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class FileSystem(BaseModel):
    """FileSystem model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    kms_key_id: Optional[str] = None
