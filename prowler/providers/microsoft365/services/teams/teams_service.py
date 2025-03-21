from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Teams(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.connect_service("Connect-MicrosoftTeams")
        self.teams_settings = self._get_teams_client_configuration()

    def _get_teams_client_configuration(self):
        logger.info("Microsoft365 - Getting teams settings...")
        settings = self.execute("Get-CsTeamsClientConfiguration | ConvertTo-Json")
        try:
            teams_settings = TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=settings.get("AllowBox", True),
                    allow_drop_box=settings.get("AllowDropBox", True),
                    allow_egnyte=settings.get("AllowEgnyte", True),
                    allow_google_drive=settings.get("AllowGoogleDrive", True),
                    allow_share_file=settings.get("AllowShareFile", True),
                )
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return teams_settings


class CloudStorageSettings(BaseModel):
    allow_box: Optional[bool]
    allow_drop_box: Optional[bool]
    allow_egnyte: Optional[bool]
    allow_google_drive: Optional[bool]
    allow_share_file: Optional[bool]


class TeamsSettings(BaseModel):
    cloud_storage_settings: CloudStorageSettings
