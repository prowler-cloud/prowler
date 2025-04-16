from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Exchange(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.organization_config = self._get_organization_config()
        self.powershell.close()

    def _get_organization_config(self):
        logger.info("Microsoft365 - Getting Exchange Organization configuration...")
        organization_configuration = self.powershell.get_organization_config()
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
