from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Teams(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_microsoft_teams()
        self.teams_settings = self._get_teams_client_configuration()
        self.global_meeting_policy = self._get_global_meeting_policy()
        self.user_settings = self._get_user_settings()
        self.powershell.close()

    def _get_teams_client_configuration(self):
        logger.info("M365 - Getting Teams settings...")
        teams_settings = None
        try:
            settings = self.powershell.get_teams_settings()
            if settings:
                teams_settings = TeamsSettings(
                    cloud_storage_settings=CloudStorageSettings(
                        allow_box=settings.get("AllowBox", True),
                        allow_drop_box=settings.get("AllowDropBox", True),
                        allow_egnyte=settings.get("AllowEgnyte", True),
                        allow_google_drive=settings.get("AllowGoogleDrive", True),
                        allow_share_file=settings.get("AllowShareFile", True),
                    ),
                    allow_email_into_channel=settings.get(
                        "AllowEmailIntoChannel", True
                    ),
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return teams_settings

    def _get_global_meeting_policy(self):
        logger.info("M365 - Getting Teams global (org-wide default) meeting policy...")
        global_meeting_policy = None
        try:
            global_meeting_policy = self.powershell.get_global_meeting_policy()
            if global_meeting_policy:
                global_meeting_policy = GlobalMeetingPolicy(
                    allow_anonymous_users_to_join_meeting=global_meeting_policy.get(
                        "AllowAnonymousUsersToJoinMeeting", True
                    ),
                    allow_anonymous_users_to_start_meeting=global_meeting_policy.get(
                        "AllowAnonymousUsersToStartMeeting", True
                    ),
                    allow_external_users_to_bypass_lobby=global_meeting_policy.get(
                        "AutoAdmittedUsers", "Everyone"
                    ),
                    allow_pstn_users_to_bypass_lobby=global_meeting_policy.get(
                        "AllowPSTNUsersToBypassLobby", True
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return global_meeting_policy

    def _get_user_settings(self):
        logger.info("M365 - Getting Teams user settings...")
        user_settings = None
        try:
            settings = self.powershell.get_user_settings()
            if settings:
                user_settings = UserSettings(
                    allow_external_access=settings.get("AllowFederatedUsers", True),
                    allow_teams_consumer=settings.get("AllowTeamsConsumer", True),
                    allow_teams_consumer_inbound=settings.get(
                        "AllowTeamsConsumerInbound", True
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return user_settings


class CloudStorageSettings(BaseModel):
    allow_box: bool
    allow_drop_box: bool
    allow_egnyte: bool
    allow_google_drive: bool
    allow_share_file: bool


class TeamsSettings(BaseModel):
    cloud_storage_settings: CloudStorageSettings
    allow_email_into_channel: bool = True


class GlobalMeetingPolicy(BaseModel):
    allow_anonymous_users_to_join_meeting: bool = True
    allow_anonymous_users_to_start_meeting: bool = True
    allow_external_users_to_bypass_lobby: str = "Everyone"
    allow_pstn_users_to_bypass_lobby: bool = True


class UserSettings(BaseModel):
    allow_external_access: bool = True
    allow_teams_consumer: bool = True
    allow_teams_consumer_inbound: bool = True
