from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Sites(GoogleWorkspaceService):
    """Google Workspace Sites service for auditing domain-level Sites policies.

    Uses the Cloud Identity Policy API v1 to read the Sites service status
    configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = SitesPolicies()
        self.policies_fetched = False
        self._fetch_sites_policies()

    def _fetch_sites_policies(self):
        """Fetch Sites policies from the Cloud Identity Policy API v1."""
        logger.info("Sites - Fetching sites policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(
                pageSize=100,
                filter='setting.type.matches("sites.*")',
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
                        value = setting.get("value", {})

                        if setting_type == "sites.service_status":
                            self.policies.service_state = value.get("serviceState")
                            logger.debug(
                                "Sites service state: " f"{self.policies.service_state}"
                            )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching Sites policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Sites policies fetched - "
                f"Service state: {self.policies.service_state}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Sites policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class SitesPolicies(BaseModel):
    """Model for domain-level Sites policy settings."""

    # sites.service_status
    service_state: Optional[str] = None
