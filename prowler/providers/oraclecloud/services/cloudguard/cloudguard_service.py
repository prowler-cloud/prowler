"""OCI Cloud Guard Service Module."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class CloudGuard(OCIService):
    """OCI Cloud Guard Service class."""

    def __init__(self, provider):
        """Initialize the Cloud Guard service."""
        super().__init__("cloudguard", provider)
        self.configuration = None
        self.__get_configuration__()

    def __get_configuration__(self):
        """Get Cloud Guard configuration."""
        try:
            cloudguard_client = self._create_oci_client(
                oci.cloud_guard.CloudGuardClient
            )

            logger.info("CloudGuard - Getting Configuration...")

            try:
                config = cloudguard_client.get_configuration(
                    compartment_id=self.audited_tenancy
                ).data

                self.configuration = CloudGuardConfiguration(
                    compartment_id=self.audited_tenancy,
                    status=config.status if hasattr(config, "status") else "DISABLED",
                    reporting_region=(
                        config.reporting_region
                        if hasattr(config, "reporting_region")
                        else None
                    ),
                )
            except Exception as error:
                logger.info(f"CloudGuard - Cloud Guard not configured: {error}")
                self.configuration = CloudGuardConfiguration(
                    compartment_id=self.audited_tenancy,
                    status="DISABLED",
                    reporting_region=None,
                )
        except Exception as error:
            logger.error(
                f"CloudGuard - Error getting Cloud Guard configuration: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class CloudGuardConfiguration(BaseModel):
    """OCI Cloud Guard Configuration model."""

    compartment_id: str
    status: str
    reporting_region: Optional[str] = None
