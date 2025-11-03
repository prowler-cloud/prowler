"""OCI Integration service."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Integration(OCIService):
    """OCI Integration service class."""

    def __init__(self, provider):
        """Initialize Integration service."""
        super().__init__("integration", provider)
        self.integration_instances = []
        self.__threading_call_by_region_and_compartment__(
            self.__list_integration_instances__
        )

    def __get_client__(self, region: str) -> oci.integration.IntegrationInstanceClient:
        """Get OCI Integration client for a region."""
        return self._create_oci_client(
            oci.integration.IntegrationInstanceClient,
            config_overrides={"region": region},
        )

    def __list_integration_instances__(self, region, compartment):
        """List all integration instances in a compartment."""
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            integration_client = self.__get_client__(region_key)

            instances = oci.pagination.list_call_get_all_results(
                integration_client.list_integration_instances,
                compartment_id=compartment.id,
            ).data

            for instance in instances:
                # Only include ACTIVE or INACTIVE or UPDATING instances
                if instance.lifecycle_state in ["ACTIVE", "INACTIVE", "UPDATING"]:
                    # Extract network endpoint details and convert to dict
                    network_endpoint_details = None
                    if (
                        hasattr(instance, "network_endpoint_details")
                        and instance.network_endpoint_details
                    ):
                        network_endpoint_details = oci.util.to_dict(
                            instance.network_endpoint_details
                        )

                    self.integration_instances.append(
                        IntegrationInstance(
                            id=instance.id,
                            display_name=instance.display_name,
                            compartment_id=instance.compartment_id,
                            region=region_key,
                            lifecycle_state=instance.lifecycle_state,
                            network_endpoint_details=network_endpoint_details,
                            instance_url=getattr(instance, "instance_url", None),
                            integration_instance_type=getattr(
                                instance, "integration_instance_type", None
                            ),
                            is_byol=getattr(instance, "is_byol", None),
                            message_packs=getattr(instance, "message_packs", None),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region_key if 'region_key' in locals() else region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class IntegrationInstance(BaseModel):
    """OCI Integration Instance model."""

    id: str
    display_name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    network_endpoint_details: Optional[dict]
    instance_url: Optional[str] = None
    integration_instance_type: Optional[str] = None
    is_byol: Optional[bool] = None
    message_packs: Optional[int] = None

    class Config:
        arbitrary_types_allowed = True
