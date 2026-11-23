from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Marketplace(GoogleWorkspaceService):
    """Google Workspace Marketplace service for auditing domain-level Marketplace policies.

    Uses the Cloud Identity Policy API v1 to read the Marketplace app access
    settings configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = MarketplacePolicies()
        self.policies_fetched = False
        self._fetch_marketplace_policies()

    def _fetch_marketplace_policies(self):
        """Fetch Marketplace policies from the Cloud Identity Policy API v1."""
        logger.info("Marketplace - Fetching marketplace policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            policies, fetch_succeeded = self._list_policies(
                service,
                'setting.type.matches("workspace_marketplace.*")',
                "fetching Marketplace policies",
            )

            for policy in self._effective_policies(policies):
                setting = policy.get("setting", {})
                setting_type = setting.get("type", "").removeprefix("settings/")
                value = setting.get("value", {})

                if setting_type == "workspace_marketplace.apps_access_options":
                    self.policies.access_level = value.get("accessLevel")
                    logger.debug(
                        "Marketplace access level: " f"{self.policies.access_level}"
                    )

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Marketplace policies fetched - "
                f"Access level: {self.policies.access_level}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Marketplace policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class MarketplacePolicies(BaseModel):
    """Model for domain-level Marketplace policy settings."""

    # workspace_marketplace.apps_access_options
    access_level: Optional[str] = None
