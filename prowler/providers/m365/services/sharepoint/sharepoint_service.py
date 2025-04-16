from asyncio import gather, get_event_loop
from typing import List, Optional

from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class SharePoint(M365Service):
    def __init__(self, provider: M365Provider):
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
        logger.info("M365 - Getting SharePoint global settings...")
        settings = None
        try:
            global_settings = await self.client.admin.sharepoint.settings.get()

            settings = SharePointSettings(
                sharingCapability=(
                    str(global_settings.sharing_capability).split(".")[-1]
                    if global_settings.sharing_capability
                    else None
                ),
                sharingAllowedDomainList=global_settings.sharing_allowed_domain_list,
                sharingBlockedDomainList=global_settings.sharing_blocked_domain_list,
                sharingDomainRestrictionMode=global_settings.sharing_domain_restriction_mode,
                legacyAuth=global_settings.is_legacy_auth_protocols_enabled,
                resharingEnabled=global_settings.is_resharing_by_external_users_enabled,
            )

        except ODataError as error:
            logger.exception(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
        except Exception as error:
            logger.exception(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None
        return settings


class SharePointSettings(BaseModel):
    sharingCapability: str
    sharingAllowedDomainList: Optional[List[str]]
    sharingBlockedDomainList: Optional[List[str]]
    sharingDomainRestrictionMode: str
    resharingEnabled: bool
    legacyAuth: bool
