from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Chat(GoogleWorkspaceService):
    """Google Workspace Chat service for auditing domain-level Chat policies.

    Uses the Cloud Identity Policy API v1 to read Chat file sharing, external
    messaging, spaces, and apps access settings configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = ChatPolicies()
        self.policies_fetched = False
        self._fetch_chat_policies()

    def _fetch_chat_policies(self):
        """Fetch Chat policies from the Cloud Identity Policy API v1."""
        logger.info("Chat - Fetching Chat policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(
                pageSize=100,
                filter='setting.type.matches("chat.*")',
            )
            fetch_succeeded = True

            while request is not None:
                try:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        if not self._is_customer_level_policy(policy):
                            continue

                        setting = policy.get("setting", {})
                        setting_type = setting.get("type", "").removeprefix("settings/")
                        logger.debug(f"Processing setting type: {setting_type}")

                        value = setting.get("value", {})

                        if setting_type == "chat.chat_file_sharing":
                            self.policies.external_file_sharing = value.get(
                                "externalFileSharing"
                            )
                            self.policies.internal_file_sharing = value.get(
                                "internalFileSharing"
                            )
                            logger.debug("Chat file sharing settings fetched.")

                        elif setting_type == "chat.external_chat_restriction":
                            self.policies.allow_external_chat = value.get(
                                "allowExternalChat"
                            )
                            self.policies.external_chat_restriction = value.get(
                                "externalChatRestriction"
                            )
                            logger.debug(
                                "Chat external chat restriction settings fetched."
                            )

                        elif setting_type == "chat.chat_external_spaces":
                            self.policies.external_spaces_enabled = value.get("enabled")
                            self.policies.external_spaces_domain_allowlist_mode = (
                                value.get("domainAllowlistMode")
                            )
                            logger.debug("Chat external spaces settings fetched.")

                        elif setting_type == "chat.chat_apps_access":
                            self.policies.enable_apps = value.get("enableApps")
                            self.policies.enable_webhooks = value.get("enableWebhooks")
                            logger.debug("Chat apps access settings fetched.")

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching Chat policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded
            logger.info("Chat policies fetched successfully.")

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Chat policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class ChatPolicies(BaseModel):
    """Model for domain-level Chat policy settings."""

    # chat.chat_file_sharing
    external_file_sharing: Optional[str] = None
    internal_file_sharing: Optional[str] = None

    # chat.external_chat_restriction
    allow_external_chat: Optional[bool] = None
    external_chat_restriction: Optional[str] = None

    # chat.chat_external_spaces
    external_spaces_enabled: Optional[bool] = None
    external_spaces_domain_allowlist_mode: Optional[str] = None

    # chat.chat_apps_access
    enable_apps: Optional[bool] = None
    enable_webhooks: Optional[bool] = None
