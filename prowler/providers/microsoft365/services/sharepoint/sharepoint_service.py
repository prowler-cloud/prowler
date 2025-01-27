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
                self._get_one_drive_shared_content(),
            )
        )
        self.settings = {self.tenant_domain: attributes[0]}
        self.one_drive_shared_content = {self.tenant_domain: attributes[1]}

    async def _get_settings(self):
        logger.info("Microsoft365 - Getting SharePoint global settings...")
        try:
            global_settings = await self.client.admin.sharepoint.settings.get()
            settings = SharePointSettings(
                sharingCapability=global_settings.get("sharingCapability"),
                sharingAllowedDomainList=global_settings.get(
                    "sharingAllowedDomainList"
                ),
                sharingBlockedDomainList=global_settings.get(
                    "sharingBlockedDomainList"
                ),
                modernAuthentication=global_settings.get(
                    "isLegacyAuthProtocolsEnabled"
                ),
            )
            return settings
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

    async def _get_one_drive_shared_content(self):
        logger.info("Microsoft365 - Getting OneDrive shared content...")
        try:
            search_request = {
                "requests": [
                    {
                        "entityTypes": ["driveItem"],
                        "query": {"queryString": "*"},
                        "sharePointOneDriveOptions": {
                            "includeContent": "sharedContent"
                        },
                    }
                ]
            }

            response = await self.client.search.query.post(body=search_request)
            hits_containers = response.get("value", [])[0].get("hitsContainers", [])
            total_shared_items = (
                hits_containers[0].get("total", 0) if hits_containers else 0
            )

            shared_content = OneDriveSharedContent(
                totalSharedContent=total_shared_items
            )
            return shared_content
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


class SharePointSettings(BaseModel):
    sharingCapability: str
    sharingAllowedDomainList: Optional[List[str]]
    sharingBlockedDomainList: Optional[List[str]]
    modernAuthentication: bool


class OneDriveSharedContent(BaseModel):
    totalSharedContent: int
