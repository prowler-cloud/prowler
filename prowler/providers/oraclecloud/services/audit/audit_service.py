"""OCI Audit Service Module."""

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Audit(OCIService):
    """OCI Audit Service class."""

    def __init__(self, provider):
        """Initialize the Audit service."""
        super().__init__("audit", provider)
        self.configuration = None
        self.__get_configuration__()

    def __get_configuration__(self):
        """Get Audit configuration."""
        try:
            audit_client = self._create_oci_client(oci.audit.AuditClient)

            logger.info("Audit - Getting Configuration...")

            try:
                config = audit_client.get_configuration(
                    compartment_id=self.audited_tenancy
                ).data

                self.configuration = AuditConfiguration(
                    compartment_id=self.audited_tenancy,
                    retention_period_days=(
                        config.retention_period_days
                        if hasattr(config, "retention_period_days")
                        else 90
                    ),
                )
            except Exception as error:
                logger.error(
                    f"Audit - Error getting audit configuration: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                self.configuration = AuditConfiguration(
                    compartment_id=self.audited_tenancy, retention_period_days=90
                )
        except Exception as error:
            logger.error(
                f"Audit - Error in audit service initialization: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class AuditConfiguration(BaseModel):
    """OCI Audit Configuration model."""

    compartment_id: str
    retention_period_days: int = 90
