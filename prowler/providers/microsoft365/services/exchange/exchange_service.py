from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Exchange(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.organization_config = self._get_organization_config()

    def _get_organization_config(self):
        logger.info("Microsoft365 - Getting Exchange Organization configuration...")
        organization_configuration = self.powershell.execute(
            "Get-OrganizationConfig | ConvertTo-Json"
        )
        try:
            organization_config = Organization(
                name=organization_configuration.get("Name", ""),
                guid=organization_configuration.get("Guid", ""),
                audit_disabled=organization_configuration.get("AuditDisabled", False),
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organization_config


class Organization(BaseModel):
    name: str
    guid: str
    audit_disabled: bool
