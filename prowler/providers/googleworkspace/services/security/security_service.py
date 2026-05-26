from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class Security(GoogleWorkspaceService):
    """Google Workspace Security service for auditing domain-level security policies.

    Uses the Cloud Identity Policy API v1 to read authentication, password,
    session, recovery, API control, and DLP settings configured in the
    Admin Console.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.policies = SecurityPolicies()
        self.policies_fetched = False
        self._fetch_security_policies()

    def _fetch_security_policies(self):
        """Fetch security policies from the Cloud Identity Policy API v1."""
        logger.info("Security - Fetching security policies...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            fetch_succeeded = True

            # Fetch 1: security.* settings
            fetch_succeeded = self._fetch_namespace(
                service, 'setting.type.matches("security.*")', fetch_succeeded
            )

            # Fetch 2: api_controls.* settings
            fetch_succeeded = self._fetch_namespace(
                service, 'setting.type.matches("api_controls.*")', fetch_succeeded
            )

            # Fetch 3: rule.dlp for DLP existence check
            fetch_succeeded = self._fetch_namespace(
                service, 'setting.type.matches("rule.dlp")', fetch_succeeded
            )

            self.policies_fetched = fetch_succeeded

            logger.info("Security policies fetched successfully.")

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching security policies",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False

    def _fetch_namespace(self, service, filter_str: str, fetch_succeeded: bool) -> bool:
        """Fetch policies for a single namespace filter."""
        try:
            request = service.policies().list(
                pageSize=100,
                filter=filter_str,
            )

            while request is not None:
                try:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        if not self._is_customer_level_policy(policy):
                            continue

                        setting = policy.get("setting", {})
                        setting_type = setting.get("type", "").removeprefix("settings/")
                        value = setting.get("value", {})

                        self._process_setting(setting_type, value)

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        f"fetching policies with filter {filter_str}",
                        self.provider.identity.customer_id,
                    )
                    return False

        except Exception as error:
            self._handle_api_error(
                error,
                f"listing policies with filter {filter_str}",
                self.provider.identity.customer_id,
            )
            return False

        return fetch_succeeded

    def _process_setting(self, setting_type: str, value: dict):
        """Process a single policy setting and populate the model."""

        # 2-Step Verification settings
        if setting_type == "security.two_step_verification_enrollment":
            self.policies.two_sv_allow_enrollment = value.get("allowEnrollment")
            logger.debug(f"2SV enrollment: {self.policies.two_sv_allow_enrollment}")

        elif setting_type == "security.two_step_verification_enforcement":
            self.policies.two_sv_enforced_from = value.get("enforcedFrom")
            logger.debug(f"2SV enforcement: {self.policies.two_sv_enforced_from}")

        elif setting_type == "security.two_step_verification_enforcement_factor":
            self.policies.two_sv_allowed_factor_set = value.get(
                "allowedSignInFactorSet"
            )
            logger.debug(f"2SV factor set: {self.policies.two_sv_allowed_factor_set}")

        elif setting_type == "security.two_step_verification_device_trust":
            self.policies.two_sv_allow_trusting_device = value.get(
                "allowTrustingDevice"
            )
            logger.debug(
                f"2SV device trust: {self.policies.two_sv_allow_trusting_device}"
            )

        elif setting_type == "security.two_step_verification_grace_period":
            self.policies.two_sv_enrollment_grace_period = value.get(
                "enrollmentGracePeriod"
            )
            logger.debug(
                f"2SV grace period: {self.policies.two_sv_enrollment_grace_period}"
            )

        elif setting_type == "security.two_step_verification_sign_in_code":
            self.policies.two_sv_backup_code_exception_period = value.get(
                "backupCodeExceptionPeriod"
            )
            logger.debug(
                f"2SV backup code period: {self.policies.two_sv_backup_code_exception_period}"
            )

        # Account recovery
        elif setting_type == "security.super_admin_account_recovery":
            self.policies.super_admin_recovery_enabled = value.get(
                "enableAccountRecovery"
            )
            logger.debug(
                f"Super admin recovery: {self.policies.super_admin_recovery_enabled}"
            )

        elif setting_type == "security.user_account_recovery":
            self.policies.user_recovery_enabled = value.get("enableAccountRecovery")
            logger.debug(f"User recovery: {self.policies.user_recovery_enabled}")

        # Advanced Protection Program
        elif setting_type == "security.advanced_protection_program":
            self.policies.advanced_protection_enrollment = value.get(
                "enableAdvancedProtectionSelfEnrollment"
            )
            self.policies.advanced_protection_security_code_option = value.get(
                "securityCodeOption"
            )
            logger.debug("Advanced Protection Program settings fetched.")

        # Login challenges
        elif setting_type == "security.login_challenges":
            self.policies.login_challenge_employee_id = value.get(
                "enableEmployeeIdChallenge"
            )
            logger.debug("Login challenges settings fetched.")

        # Password policy
        elif setting_type == "security.password":
            self.policies.password_minimum_length = value.get("minimumLength")
            self.policies.password_maximum_length = value.get("maximumLength")
            self.policies.password_allowed_strength = value.get("allowedStrength")
            self.policies.password_allow_reuse = value.get("allowReuse")
            self.policies.password_enforce_at_login = value.get(
                "enforceRequirementsAtLogin"
            )
            self.policies.password_expiration_duration = value.get("expirationDuration")
            logger.debug("Password policy settings fetched.")

        # Less secure apps
        elif setting_type == "security.less_secure_apps":
            self.policies.less_secure_apps_allowed = value.get("allowLessSecureApps")
            logger.debug(f"Less secure apps: {self.policies.less_secure_apps_allowed}")

        # Session controls
        elif setting_type == "security.session_controls":
            self.policies.web_session_duration = value.get("webSessionDuration")
            logger.debug(f"Web session duration: {self.policies.web_session_duration}")

        # Passkeys restriction
        elif setting_type == "security.passkeys_restriction":
            self.policies.passkeys_type = value.get("allowedPasskeysType")
            logger.debug(f"Passkeys type: {self.policies.passkeys_type}")

        # API controls - internal apps
        elif setting_type == "api_controls.internal_apps":
            self.policies.trust_internal_apps = value.get("trustInternalApps")
            logger.debug(f"Trust internal apps: {self.policies.trust_internal_apps}")

        # API controls - google services
        elif setting_type == "api_controls.google_services":
            services = value.get("services", [])
            for svc in services:
                if svc.get("isEnabled") is False:
                    self.policies.google_services_restricted = True
                    break
            if self.policies.google_services_restricted is None:
                self.policies.google_services_restricted = False
            logger.debug(
                f"Google services restricted: {self.policies.google_services_restricted}"
            )

        # DLP rules
        elif setting_type == "rule.dlp":
            state = value.get("state")
            triggers = value.get("triggers", [])
            if state == "ACTIVE" and "google.workspace.drive.file.v1.share" in triggers:
                self.policies.dlp_drive_rules_exist = True
            logger.debug(f"DLP rule: state={state}, triggers={triggers}")


class SecurityPolicies(BaseModel):
    """Model for domain-level Security policy settings."""

    # security.two_step_verification_enrollment
    two_sv_allow_enrollment: Optional[bool] = None
    # security.two_step_verification_enforcement
    two_sv_enforced_from: Optional[str] = None
    # security.two_step_verification_enforcement_factor
    two_sv_allowed_factor_set: Optional[str] = None
    # security.two_step_verification_device_trust
    two_sv_allow_trusting_device: Optional[bool] = None
    # security.two_step_verification_grace_period
    two_sv_enrollment_grace_period: Optional[str] = None
    # security.two_step_verification_sign_in_code
    two_sv_backup_code_exception_period: Optional[str] = None
    # security.super_admin_account_recovery
    super_admin_recovery_enabled: Optional[bool] = None
    # security.user_account_recovery
    user_recovery_enabled: Optional[bool] = None
    # security.advanced_protection_program
    advanced_protection_enrollment: Optional[bool] = None
    advanced_protection_security_code_option: Optional[str] = None
    # security.login_challenges
    login_challenge_employee_id: Optional[bool] = None
    # security.password
    password_minimum_length: Optional[int] = None
    password_maximum_length: Optional[int] = None
    password_allowed_strength: Optional[str] = None
    password_allow_reuse: Optional[bool] = None
    password_enforce_at_login: Optional[bool] = None
    password_expiration_duration: Optional[str] = None
    # security.less_secure_apps
    less_secure_apps_allowed: Optional[bool] = None
    # security.session_controls
    web_session_duration: Optional[str] = None
    # security.passkeys_restriction
    passkeys_type: Optional[str] = None
    # api_controls.internal_apps
    trust_internal_apps: Optional[bool] = None
    # api_controls.google_services
    google_services_restricted: Optional[bool] = None
    # rule.dlp
    dlp_drive_rules_exist: Optional[bool] = None
