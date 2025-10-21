"""OCI Analytics service."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Analytics(OCIService):
    """OCI Analytics service class."""

    def __init__(self, provider):
        """Initialize Analytics service."""
        super().__init__("analytics", provider)
        self.analytics_instances = []
        self.__threading_call_by_region_and_compartment__(
            self.__list_analytics_instances__
        )

    def __get_client__(self, region: str) -> oci.analytics.AnalyticsClient:
        """Get OCI Analytics client for a region."""
        return self._create_oci_client(
            oci.analytics.AnalyticsClient, config_overrides={"region": region}
        )

    def __list_analytics_instances__(self, region, compartment):
        """List all analytics instances in a compartment."""
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            analytics_client = self.__get_client__(region_key)

            instances = oci.pagination.list_call_get_all_results(
                analytics_client.list_analytics_instances, compartment_id=compartment.id
            ).data

            for instance in instances:
                # Only include ACTIVE or INACTIVE or UPDATING instances
                if instance.lifecycle_state in ["ACTIVE", "INACTIVE", "UPDATING"]:
                    # Extract network endpoint details
                    network_endpoint_type = None
                    whitelisted_ips = []

                    if (
                        hasattr(instance, "network_endpoint_details")
                        and instance.network_endpoint_details
                    ):
                        network_endpoint_type = getattr(
                            instance.network_endpoint_details,
                            "network_endpoint_type",
                            None,
                        )
                        whitelisted_ips = (
                            getattr(
                                instance.network_endpoint_details, "whitelisted_ips", []
                            )
                            or []
                        )

                    self.analytics_instances.append(
                        AnalyticsInstance(
                            id=instance.id,
                            name=instance.name,
                            compartment_id=instance.compartment_id,
                            region=region_key,
                            lifecycle_state=instance.lifecycle_state,
                            network_endpoint_type=network_endpoint_type,
                            whitelisted_ips=whitelisted_ips,
                            description=getattr(instance, "description", None),
                            email_notification=getattr(
                                instance, "email_notification", None
                            ),
                            feature_set=getattr(instance, "feature_set", None),
                            service_url=getattr(instance, "service_url", None),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region_key if 'region_key' in locals() else region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class AnalyticsInstance(BaseModel):
    """OCI Analytics Instance model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    network_endpoint_type: Optional[str]
    whitelisted_ips: list[str]
    description: Optional[str] = None
    email_notification: Optional[str] = None
    feature_set: Optional[str] = None
    service_url: Optional[str] = None
