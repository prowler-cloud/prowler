from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class AdditionalServices(GoogleWorkspaceService):
    """Google Workspace Additional Services for auditing domain-level service toggles.

    Uses the Cloud Identity Policy API v1 to read the service status of
    additional Google services configured in the Admin Console, such as
    the external Google Groups access toggle.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = AdditionalServicesPolicies()
        self.policies_fetched = False
        self._fetch_additional_services_policies()

    def _fetch_additional_services_policies(self):
        """Fetch Additional Services policies from the Cloud Identity Policy API v1."""
        logger.info("Additional Services - Fetching policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(
                pageSize=100,
                filter='setting.type.matches("groups.service_status")',
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

                        if setting_type == "groups.service_status":
                            self.policies.groups_service_state = value.get(
                                "serviceState"
                            )
                            logger.debug(
                                "Additional Services - Groups service state: "
                                f"{self.policies.groups_service_state}"
                            )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching Additional Services policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Additional Services policies fetched - "
                f"Groups service state: {self.policies.groups_service_state}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Additional Services policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class AdditionalServicesPolicies(BaseModel):
    """Model for domain-level Additional Google Services policy settings."""

    # groups.service_status
    groups_service_state: Optional[str] = None
