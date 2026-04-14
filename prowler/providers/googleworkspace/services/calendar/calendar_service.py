from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Calendar(GoogleWorkspaceService):
    """Google Workspace Calendar service for auditing domain-level calendar policies.

    Uses the Cloud Identity Policy API v1 to read calendar sharing
    and invitation settings configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = CalendarPolicies()
        self.policies_fetched = False
        self._fetch_calendar_policies()

    def _fetch_calendar_policies(self):
        """Fetch calendar policies from the Cloud Identity Policy API v1."""
        logger.info("Calendar - Fetching calendar policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(pageSize=100)
            fetch_succeeded = True

            while request is not None:
                try:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        if not self._is_customer_level_policy(policy):
                            continue
                        setting = policy.get("setting", {})
                        setting_type = setting.get("type", "").removeprefix("settings/")
                        value = setting.get("value", {})

                        if (
                            setting_type
                            == "calendar.primary_calendar_max_allowed_external_sharing"
                        ):
                            self.policies.primary_calendar_external_sharing = value.get(
                                "maxAllowedExternalSharing"
                            )
                            logger.debug(
                                "Primary calendar external sharing: "
                                f"{self.policies.primary_calendar_external_sharing}"
                            )

                        elif (
                            setting_type
                            == "calendar.secondary_calendar_max_allowed_external_sharing"
                        ):
                            self.policies.secondary_calendar_external_sharing = (
                                value.get("maxAllowedExternalSharing")
                            )
                            logger.debug(
                                "Secondary calendar external sharing: "
                                f"{self.policies.secondary_calendar_external_sharing}"
                            )

                        elif setting_type == "calendar.external_invitations":
                            self.policies.external_invitations_warning = value.get(
                                "warnOnInvite"
                            )
                            logger.debug(
                                "External invitations warning: "
                                f"{self.policies.external_invitations_warning}"
                            )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching calendar policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Calendar policies fetched - "
                f"Primary sharing: {self.policies.primary_calendar_external_sharing}, "
                f"Secondary sharing: {self.policies.secondary_calendar_external_sharing}, "
                f"Invitation warnings: {self.policies.external_invitations_warning}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching calendar policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class CalendarPolicies(BaseModel):
    """Model for domain-level Calendar policy settings."""

    primary_calendar_external_sharing: Optional[str] = None
    secondary_calendar_external_sharing: Optional[str] = None
    external_invitations_warning: Optional[bool] = None
