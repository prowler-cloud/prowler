"""OCI Database service."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Database(OCIService):
    """OCI Database service class."""

    def __init__(self, provider):
        """Initialize Database service."""
        super().__init__("database", provider)
        self.autonomous_databases = []
        self.__threading_call_by_region_and_compartment__(
            self.__list_autonomous_databases__
        )

    def __get_client__(self, region: str) -> oci.database.DatabaseClient:
        """Get OCI Database client for a region."""
        return self._create_oci_client(
            oci.database.DatabaseClient, config_overrides={"region": region}
        )

    def __list_autonomous_databases__(self, region, compartment):
        """List all autonomous databases in a compartment."""
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            database_client = self.__get_client__(region_key)

            autonomous_dbs = oci.pagination.list_call_get_all_results(
                database_client.list_autonomous_databases, compartment_id=compartment.id
            ).data

            for adb in autonomous_dbs:
                # Only include databases not in TERMINATED, TERMINATING, or UNAVAILABLE states
                if adb.lifecycle_state not in [
                    oci.database.models.AutonomousDatabaseSummary.LIFECYCLE_STATE_TERMINATED,
                    oci.database.models.AutonomousDatabaseSummary.LIFECYCLE_STATE_TERMINATING,
                    oci.database.models.AutonomousDatabaseSummary.LIFECYCLE_STATE_UNAVAILABLE,
                ]:
                    self.autonomous_databases.append(
                        AutonomousDatabase(
                            id=adb.id,
                            display_name=adb.display_name,
                            compartment_id=adb.compartment_id,
                            region=region_key,
                            lifecycle_state=adb.lifecycle_state,
                            whitelisted_ips=(
                                adb.whitelisted_ips if adb.whitelisted_ips else []
                            ),
                            subnet_id=adb.subnet_id,
                            db_name=getattr(adb, "db_name", None),
                            db_workload=getattr(adb, "db_workload", None),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region_key if 'region_key' in locals() else region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class AutonomousDatabase(BaseModel):
    """OCI Autonomous Database model."""

    id: str
    display_name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    whitelisted_ips: list[str]
    subnet_id: Optional[str]
    db_name: Optional[str] = None
    db_workload: Optional[str] = None
