from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import (
    GoogleWorkspaceService,
    ServicePolicies,
)


class Groups(GoogleWorkspaceService):
    """Google Workspace Groups for Business service for auditing domain-level group policies.

    Uses the Cloud Identity Policy API v1 to read group sharing, creation,
    and conversation viewing settings configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = GroupsPolicies()
        self.policies_fetched = False
        self._fetch_groups_for_business_policies()

    def _fetch_groups_for_business_policies(self):
        """Fetch Groups for Business policies from the Cloud Identity Policy API v1."""
        logger.info("Groups for Business - Fetching policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            policies, fetch_succeeded = self._list_policies(
                service,
                'setting.type.matches("groups_for_business.*")',
                "fetching Groups for Business policies",
            )

            (
                self.policies.service_state,
                self.policies.service_state_overridden,
            ) = self._service_status(policies, "groups_for_business.service_status")

            for policy in self._effective_policies(policies):
                setting = policy.get("setting", {})
                setting_type = setting.get("type", "").removeprefix("settings/")
                self._process_setting(setting_type, setting.get("value", {}))

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Groups for Business policies fetched - "
                f"Collaboration: {self.policies.collaboration_capability}, "
                f"Creation: {self.policies.create_groups_access_level}, "
                f"View topics: {self.policies.view_topics_default_access_level}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Groups for Business policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False

    def _process_setting(self, setting_type: str, value: dict):
        """Populate the model from a single policy setting."""
        logger.debug(f"Processing setting type: {setting_type}")

        if setting_type == "groups_for_business.groups_sharing":
            self.policies.collaboration_capability = value.get(
                "collaborationCapability"
            )
            self.policies.create_groups_access_level = value.get(
                "createGroupsAccessLevel"
            )
            self.policies.owners_can_allow_external_members = value.get(
                "ownersCanAllowExternalMembers"
            )
            self.policies.owners_can_allow_incoming_mail_from_public = value.get(
                "ownersCanAllowIncomingMailFromPublic"
            )
            self.policies.view_topics_default_access_level = value.get(
                "viewTopicsDefaultAccessLevel"
            )
            self.policies.owners_can_hide_groups = value.get("ownersCanHideGroups")
            self.policies.new_groups_are_hidden = value.get("newGroupsAreHidden")
            logger.debug("Groups for Business sharing settings fetched.")


class GroupsPolicies(ServicePolicies):
    """Model for domain-level Groups for Business policy settings."""

    # groups_for_business.groups_sharing
    collaboration_capability: Optional[str] = None
    create_groups_access_level: Optional[str] = None
    owners_can_allow_external_members: Optional[bool] = None
    owners_can_allow_incoming_mail_from_public: Optional[bool] = None
    view_topics_default_access_level: Optional[str] = None
    owners_can_hide_groups: Optional[bool] = None
    new_groups_are_hidden: Optional[bool] = None
