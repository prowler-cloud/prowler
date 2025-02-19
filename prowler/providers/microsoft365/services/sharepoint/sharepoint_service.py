from asyncio import gather, get_event_loop
from typing import List, Optional

from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class SharePoint(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        loop = get_event_loop()
        self.tenant_domain = provider.identity.tenant_domain
        attributes = loop.run_until_complete(
            gather(
                self._get_settings(),
            )
        )
        self.settings = attributes[0]

    async def _get_settings(self):
        logger.info("Microsoft365 - Getting SharePoint global settings...")
        settings = {}
        try:
            global_settings = await self.client.admin.sharepoint.settings.get()

            sharepoint_settings = SharePointSettings(
                id=self.tenant_domain,
                sharingCapability=(
                    str(global_settings.sharing_capability).split(".")[-1]
                    if global_settings.sharing_capability
                    else None
                ),
                sharingAllowedDomainList=global_settings.sharing_allowed_domain_list,
                sharingBlockedDomainList=global_settings.sharing_blocked_domain_list,
                sharingDomainRestrictionMode=global_settings.sharing_domain_restriction_mode,
                modernAuthentication=global_settings.is_legacy_auth_protocols_enabled,
                resharingEnabled=global_settings.is_resharing_by_external_users_enabled,
            )
            settings[self.tenant_domain] = sharepoint_settings

        except ODataError as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
        return settings


class SharePointSettings(BaseModel):
    id: str
    sharingCapability: str
    sharingAllowedDomainList: Optional[List[str]]
    sharingBlockedDomainList: Optional[List[str]]
    sharingDomainRestrictionMode: str
    resharingEnabled: bool
    modernAuthentication: bool
