from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import (
    GoogleWorkspaceService,
    ServicePolicies,
)


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

            policies, fetch_succeeded = self._list_policies(
                service,
                'setting.type.matches("calendar.*")',
                "fetching calendar policies",
            )

            (
                self.policies.service_state,
                self.policies.service_state_overridden,
            ) = self._service_status(policies, "calendar.service_status")

            for policy in self._effective_policies(policies):
                setting = policy.get("setting", {})
                setting_type = setting.get("type", "").removeprefix("settings/")
                self._process_setting(setting_type, setting.get("value", {}))

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

    def _process_setting(self, setting_type: str, value: dict):
        """Populate the model from a single policy setting."""
        if setting_type == "calendar.primary_calendar_max_allowed_external_sharing":
            self.policies.primary_calendar_external_sharing = value.get(
                "maxAllowedExternalSharing"
            )
            logger.debug(
                "Primary calendar external sharing: "
                f"{self.policies.primary_calendar_external_sharing}"
            )

        elif setting_type == "calendar.secondary_calendar_max_allowed_external_sharing":
            self.policies.secondary_calendar_external_sharing = value.get(
                "maxAllowedExternalSharing"
            )
            logger.debug(
                "Secondary calendar external sharing: "
                f"{self.policies.secondary_calendar_external_sharing}"
            )

        elif setting_type == "calendar.external_invitations":
            self.policies.external_invitations_warning = value.get("warnOnInvite")
            logger.debug(
                "External invitations warning: "
                f"{self.policies.external_invitations_warning}"
            )


class CalendarPolicies(ServicePolicies):
    """Model for domain-level Calendar policy settings."""

    primary_calendar_external_sharing: Optional[str] = None
    secondary_calendar_external_sharing: Optional[str] = None
    external_invitations_warning: Optional[bool] = None
