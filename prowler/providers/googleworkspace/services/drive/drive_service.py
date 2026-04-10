from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Drive(GoogleWorkspaceService):
    """Google Workspace Drive and Docs service for auditing domain-level Drive policies.

    Uses the Cloud Identity Policy API v1 to read Drive and Docs sharing,
    shared drive creation, and Drive for desktop settings configured in the
    Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = DrivePolicies()
        self.policies_fetched = False
        self._fetch_drive_policies()

    def _fetch_drive_policies(self):
        """Fetch Drive and Docs policies from the Cloud Identity Policy API v1."""
        logger.info("Drive - Fetching Drive and Docs policies...")

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
                        setting = policy.get("setting", {})
                        setting_type = setting.get("type", "").removeprefix("settings/")
                        value = setting.get("value", {})

                        if setting_type == "drive_and_docs.external_sharing":
                            self.policies.external_sharing_mode = value.get(
                                "externalSharingMode"
                            )
                            self.policies.warn_for_external_sharing = value.get(
                                "warnForExternalSharing"
                            )
                            self.policies.warn_for_sharing_outside_allowlisted_domains = value.get(
                                "warnForSharingOutsideAllowlistedDomains"
                            )
                            self.policies.allow_publishing_files = value.get(
                                "allowPublishingFiles"
                            )
                            self.policies.access_checker_suggestions = value.get(
                                "accessCheckerSuggestions"
                            )
                            self.policies.allowed_parties_for_distributing_content = (
                                value.get("allowedPartiesForDistributingContent")
                            )
                            logger.debug(
                                "Drive external sharing settings fetched: "
                                f"mode={self.policies.external_sharing_mode}, "
                                f"warn={self.policies.warn_for_external_sharing}, "
                                f"publish={self.policies.allow_publishing_files}"
                            )

                        elif setting_type == "drive_and_docs.shared_drive_creation":
                            self.policies.allow_shared_drive_creation = value.get(
                                "allowSharedDriveCreation"
                            )
                            self.policies.allow_managers_to_override_settings = (
                                value.get("allowManagersToOverrideSettings")
                            )
                            self.policies.allow_non_member_access = value.get(
                                "allowNonMemberAccess"
                            )
                            self.policies.allowed_parties_for_download_print_copy = (
                                value.get("allowedPartiesForDownloadPrintCopy")
                            )
                            logger.debug(
                                "Drive shared drive creation settings fetched: "
                                f"creation={self.policies.allow_shared_drive_creation}, "
                                f"managers_override={self.policies.allow_managers_to_override_settings}"
                            )

                        elif setting_type == "drive_and_docs.drive_for_desktop":
                            self.policies.allow_drive_for_desktop = value.get(
                                "allowDriveForDesktop"
                            )
                            logger.debug(
                                "Drive for desktop setting fetched: "
                                f"{self.policies.allow_drive_for_desktop}"
                            )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching Drive and Docs policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Drive and Docs policies fetched - "
                f"External sharing mode: {self.policies.external_sharing_mode}, "
                f"Shared drive creation: {self.policies.allow_shared_drive_creation}, "
                f"Drive for desktop: {self.policies.allow_drive_for_desktop}"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Drive and Docs policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class DrivePolicies(BaseModel):
    """Model for domain-level Drive and Docs policy settings."""

    # drive_and_docs.external_sharing
    external_sharing_mode: Optional[str] = None
    warn_for_external_sharing: Optional[bool] = None
    warn_for_sharing_outside_allowlisted_domains: Optional[bool] = None
    allow_publishing_files: Optional[bool] = None
    access_checker_suggestions: Optional[str] = None
    allowed_parties_for_distributing_content: Optional[str] = None

    # drive_and_docs.shared_drive_creation
    allow_shared_drive_creation: Optional[bool] = None
    allow_managers_to_override_settings: Optional[bool] = None
    allow_non_member_access: Optional[bool] = None
    allowed_parties_for_download_print_copy: Optional[str] = None

    # drive_and_docs.drive_for_desktop
    allow_drive_for_desktop: Optional[bool] = None
