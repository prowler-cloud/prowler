from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Purview(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.audit_log_config = self._get_audit_log_config()
        self.powershell.close()

    def _get_audit_log_config(self):
        logger.info("M365 - Getting Admin Audit Log settings...")
        audit_log_config = None
        try:
            audit_log_config_response = self.powershell.get_audit_log_config()
            audit_log_config = AuditLogConfig(
                audit_log_search=audit_log_config_response.get(
                    "UnifiedAuditLogIngestionEnabled", False
                )
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return audit_log_config


class AuditLogConfig(BaseModel):
    audit_log_search: bool
