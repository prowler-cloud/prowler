from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Purview(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.audit_log_config = self._get_audit_log_config()

    def _get_audit_log_config(self):
        logger.info("Microsoft365 - Getting Purview settings...")
        audit_log_config = self.powershell.execute(
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled | ConvertTo-Json"
        )
        try:
            audit_log_config = AuditLogConfig(
                audit_log_search=audit_log_config.get(
                    "UnifiedAuditLogIngestionEnabled", False
                )
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return audit_log_config


class AuditLogConfig(BaseModel):
    audit_log_search: bool = False
