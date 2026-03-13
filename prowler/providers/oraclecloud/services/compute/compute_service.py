"""OCI Compute Service Module."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Compute(OCIService):
    """OCI Compute Service class to retrieve compute instances."""

    def __init__(self, provider):
        """
        Initialize the Compute service.

        Args:
            provider: The OCI provider instance
        """
        super().__init__("compute", provider)
        self.instances = []
        self.__threading_call__(self.__list_instances__)

    def __get_client__(self, region):
        """
        Get the Compute client for a region.

        Args:
            region: Region key

        Returns:
            Compute client instance
        """
        client_region = self.regional_clients.get(region)
        if client_region:
            return self._create_oci_client(oci.core.ComputeClient)
        return None

    def __list_instances__(self, regional_client):
        """
        List all compute instances in the compartments.

        Args:
            regional_client: Regional OCI client
        """
        try:
            compute_client = self.__get_client__(regional_client.region)
            if not compute_client:
                return

            logger.info(f"Compute - Listing Instances in {regional_client.region}...")

            for compartment in self.audited_compartments:
                try:
                    instances = oci.pagination.list_call_get_all_results(
                        compute_client.list_instances, compartment_id=compartment.id
                    ).data

                    for instance in instances:
                        if instance.lifecycle_state not in [
                            "TERMINATED",
                            "TERMINATING",
                        ]:
                            # Get instance metadata options
                            metadata_options = (
                                instance.instance_options.are_legacy_imds_endpoints_disabled
                                if hasattr(instance, "instance_options")
                                and hasattr(
                                    instance.instance_options,
                                    "are_legacy_imds_endpoints_disabled",
                                )
                                else None
                            )

                            # Get secure boot status
                            is_secure_boot_enabled = (
                                instance.platform_config.is_secure_boot_enabled
                                if hasattr(instance, "platform_config")
                                and hasattr(
                                    instance.platform_config, "is_secure_boot_enabled"
                                )
                                else False
                            )

                            # Get in-transit encryption status from launch options
                            is_pv_encryption_in_transit_enabled = (
                                instance.launch_options.is_pv_encryption_in_transit_enabled
                                if hasattr(instance, "launch_options")
                                and hasattr(
                                    instance.launch_options,
                                    "is_pv_encryption_in_transit_enabled",
                                )
                                else None
                            )

                            self.instances.append(
                                Instance(
                                    id=instance.id,
                                    name=(
                                        instance.display_name
                                        if hasattr(instance, "display_name")
                                        else instance.id
                                    ),
                                    compartment_id=compartment.id,
                                    region=regional_client.region,
                                    lifecycle_state=instance.lifecycle_state,
                                    are_legacy_imds_endpoints_disabled=metadata_options,
                                    is_secure_boot_enabled=is_secure_boot_enabled,
                                    is_pv_encryption_in_transit_enabled=is_pv_encryption_in_transit_enabled,
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


# Service Models
class Instance(BaseModel):
    """OCI Compute Instance model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    are_legacy_imds_endpoints_disabled: Optional[bool] = None
    is_secure_boot_enabled: bool = False
    is_pv_encryption_in_transit_enabled: Optional[bool] = None
