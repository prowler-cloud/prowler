from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Gmail(GoogleWorkspaceService):
    """Google Workspace Gmail service for auditing domain-level Gmail policies.

    Uses the Cloud Identity Policy API v1 to read Gmail safety, access,
    delegation, and compliance settings configured in the Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = GmailPolicies()
        self.policies_fetched = False
        self._fetch_gmail_policies()

    def _fetch_gmail_policies(self):
        """Fetch Gmail policies from the Cloud Identity Policy API v1."""
        logger.info("Gmail - Fetching Gmail policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(pageSize=100)
            fetch_succeeded = True
            customer_level_settings = set()

            while request is not None:
                try:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        if policy.get("policyQuery", {}).get("group"):
                            continue

                        setting = policy.get("setting", {})
                        setting_type = setting.get("type", "").removeprefix("settings/")
                        logger.debug(f"Processing setting type: {setting_type}")

                        is_customer_level = self._is_customer_level_policy(policy)
                        if (
                            not is_customer_level
                            and setting_type in customer_level_settings
                        ):
                            continue
                        if is_customer_level:
                            customer_level_settings.add(setting_type)

                        value = setting.get("value", {})

                        if setting_type == "gmail.mail_delegation":
                            self.policies.enable_mail_delegation = value.get(
                                "enableMailDelegation"
                            )
                            logger.debug("Gmail mail delegation setting fetched.")

                        elif setting_type == "gmail.email_attachment_safety":
                            self.policies.encrypted_attachment_protection_consequence = value.get(
                                "encryptedAttachmentProtectionConsequence"
                            )
                            self.policies.script_attachment_protection_consequence = (
                                value.get("scriptAttachmentProtectionConsequence")
                            )
                            self.policies.anomalous_attachment_protection_consequence = value.get(
                                "anomalousAttachmentProtectionConsequence"
                            )
                            logger.debug("Gmail attachment safety settings fetched.")

                        elif setting_type == "gmail.links_and_external_images":
                            self.policies.enable_shortener_scanning = value.get(
                                "enableShortenerScanning"
                            )
                            self.policies.enable_external_image_scanning = value.get(
                                "enableExternalImageScanning"
                            )
                            self.policies.enable_aggressive_warnings_on_untrusted_links = value.get(
                                "enableAggressiveWarningsOnUntrustedLinks"
                            )
                            logger.debug(
                                "Gmail links and external images settings fetched."
                            )

                        elif setting_type == "gmail.spoofing_and_authentication":
                            self.policies.domain_spoofing_consequence = value.get(
                                "domainSpoofingConsequence"
                            )
                            self.policies.employee_name_spoofing_consequence = (
                                value.get("employeeNameSpoofingConsequence")
                            )
                            self.policies.inbound_domain_spoofing_consequence = (
                                value.get("inboundDomainSpoofingConsequence")
                            )
                            self.policies.unauthenticated_email_consequence = value.get(
                                "unauthenticatedEmailConsequence"
                            )
                            self.policies.groups_spoofing_consequence = value.get(
                                "groupsSpoofingConsequence"
                            )
                            logger.debug(
                                "Gmail spoofing and authentication settings fetched."
                            )

                        elif setting_type == "gmail.pop_access":
                            self.policies.enable_pop_access = value.get(
                                "enablePopAccess"
                            )
                            logger.debug("Gmail POP access setting fetched.")

                        elif setting_type == "gmail.imap_access":
                            self.policies.enable_imap_access = value.get(
                                "enableImapAccess"
                            )
                            logger.debug("Gmail IMAP access setting fetched.")

                        elif setting_type == "gmail.auto_forwarding":
                            self.policies.enable_auto_forwarding = value.get(
                                "enableAutoForwarding"
                            )
                            logger.debug("Gmail auto-forwarding setting fetched.")

                        elif setting_type == "gmail.per_user_outbound_gateway":
                            self.policies.allow_per_user_outbound_gateway = value.get(
                                "allowUsersToUseExternalSmtpServers"
                            )
                            logger.debug(
                                "Gmail per-user outbound gateway setting fetched."
                            )

                        elif (
                            setting_type
                            == "gmail.enhanced_pre_delivery_message_scanning"
                        ):
                            self.policies.enable_enhanced_pre_delivery_scanning = (
                                value.get("enableImprovedSuspiciousContentDetection")
                            )
                            logger.debug(
                                "Gmail enhanced pre-delivery scanning setting fetched."
                            )

                        elif setting_type == "gmail.comprehensive_mail_storage":
                            self.policies.comprehensive_mail_storage_enabled = (
                                value.get("ruleId") is not None
                            )
                            logger.debug(
                                "Gmail comprehensive mail storage setting fetched."
                            )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching Gmail policies",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            self.policies_fetched = fetch_succeeded or self.policies != GmailPolicies()
            logger.info("Gmail policies fetched successfully.")

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching Gmail policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False


class GmailPolicies(BaseModel):
    """Model for domain-level Gmail policy settings."""

    # gmail.mail_delegation
    enable_mail_delegation: Optional[bool] = None

    # gmail.email_attachment_safety
    encrypted_attachment_protection_consequence: Optional[str] = None
    script_attachment_protection_consequence: Optional[str] = None
    anomalous_attachment_protection_consequence: Optional[str] = None

    # gmail.links_and_external_images
    enable_shortener_scanning: Optional[bool] = None
    enable_external_image_scanning: Optional[bool] = None
    enable_aggressive_warnings_on_untrusted_links: Optional[bool] = None

    # gmail.spoofing_and_authentication
    domain_spoofing_consequence: Optional[str] = None
    employee_name_spoofing_consequence: Optional[str] = None
    inbound_domain_spoofing_consequence: Optional[str] = None
    unauthenticated_email_consequence: Optional[str] = None
    groups_spoofing_consequence: Optional[str] = None

    # gmail.pop_access
    enable_pop_access: Optional[bool] = None

    # gmail.imap_access
    enable_imap_access: Optional[bool] = None

    # gmail.auto_forwarding
    enable_auto_forwarding: Optional[bool] = None

    # gmail.per_user_outbound_gateway
    allow_per_user_outbound_gateway: Optional[bool] = None

    # gmail.enhanced_pre_delivery_message_scanning
    enable_enhanced_pre_delivery_scanning: Optional[bool] = None

    # gmail.comprehensive_mail_storage
    comprehensive_mail_storage_enabled: Optional[bool] = None
