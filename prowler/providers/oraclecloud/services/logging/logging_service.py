"""OCI Logging Service Module."""

from datetime import datetime
from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Logging(OCIService):
    """OCI Logging Service class to retrieve log groups and logs."""

    def __init__(self, provider):
        """
        Initialize the Logging service.

        Args:
            provider: The OCI provider instance
        """
        super().__init__("logging", provider)
        self.log_groups = []
        self.logs = []
        self.__threading_call_by_region_and_compartment__(self.__list_log_groups__)
        self.__threading_call_by_region_and_compartment__(self.__list_logs__)

    def __get_client__(self, region):
        """
        Get the Logging Management client for a region.

        Args:
            region: Region key

        Returns:
            Logging Management client instance
        """
        return self._create_oci_client(
            oci.logging.LoggingManagementClient, config_overrides={"region": region}
        )

    def __list_log_groups__(self, region, compartment):
        """
        List all log groups in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            logging_client = self.__get_client__(region_key)

            logger.info(
                f"Logging - Listing Log Groups in {region_key} - {compartment.name}..."
            )

            log_groups_data = oci.pagination.list_call_get_all_results(
                logging_client.list_log_groups, compartment_id=compartment.id
            ).data

            for log_group in log_groups_data:
                if log_group.lifecycle_state != "DELETED":
                    self.log_groups.append(
                        LogGroup(
                            id=log_group.id,
                            display_name=log_group.display_name,
                            description=(
                                log_group.description
                                if hasattr(log_group, "description")
                                and log_group.description
                                else None
                            ),
                            compartment_id=compartment.id,
                            time_created=log_group.time_created,
                            lifecycle_state=log_group.lifecycle_state,
                            region=region_key,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region_key if 'region_key' in locals() else region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_logs__(self, region, compartment):
        """
        List all logs in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            logging_client = self.__get_client__(region_key)

            logger.info(
                f"Logging - Listing Logs in {region_key} - {compartment.name}..."
            )

            # Get all log groups in this compartment/region
            compartment_log_groups = [
                lg
                for lg in self.log_groups
                if lg.compartment_id == compartment.id and lg.region == region_key
            ]

            for log_group in compartment_log_groups:
                try:
                    logs_data = oci.pagination.list_call_get_all_results(
                        logging_client.list_logs, log_group_id=log_group.id
                    ).data

                    for log in logs_data:
                        if log.lifecycle_state != "DELETED":
                            # Extract configuration details
                            source_service = None
                            source_category = None
                            source_resource = None

                            if hasattr(log, "configuration") and log.configuration:
                                config = log.configuration
                                if hasattr(config, "source") and config.source:
                                    source = config.source
                                    source_service = getattr(source, "service", None)
                                    source_category = getattr(source, "category", None)
                                    source_resource = getattr(source, "resource", None)

                            self.logs.append(
                                Log(
                                    id=log.id,
                                    display_name=log.display_name,
                                    log_group_id=log_group.id,
                                    log_type=log.log_type,
                                    compartment_id=compartment.id,
                                    time_created=log.time_created,
                                    lifecycle_state=log.lifecycle_state,
                                    is_enabled=(
                                        log.is_enabled
                                        if hasattr(log, "is_enabled")
                                        else True
                                    ),
                                    source_service=source_service,
                                    source_category=source_category,
                                    source_resource=source_resource,
                                    region=region_key,
                                )
                            )
                except Exception as log_error:
                    logger.error(
                        f"Error listing logs for log group {log_group.id}: {log_error.__class__.__name__}[{log_error.__traceback__.tb_lineno}]: {log_error}"
                    )

        except Exception as error:
            logger.error(
                f"{region_key if 'region_key' in locals() else region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class LogGroup(BaseModel):
    """OCI Log Group model."""

    id: str
    display_name: str
    description: Optional[str]
    compartment_id: str
    time_created: datetime
    lifecycle_state: str
    region: str


class Log(BaseModel):
    """OCI Log model."""

    id: str
    display_name: str
    log_group_id: str
    log_type: str
    compartment_id: str
    time_created: datetime
    lifecycle_state: str
    is_enabled: bool
    source_service: Optional[str]
    source_category: Optional[str]
    source_resource: Optional[str]
    region: str
