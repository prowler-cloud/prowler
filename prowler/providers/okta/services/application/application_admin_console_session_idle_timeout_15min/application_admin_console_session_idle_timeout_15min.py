from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.application.application_client import (
    application_client,
)
from prowler.providers.okta.services.application.application_service import (
    AdminConsoleAppSettings,
)
from prowler.providers.okta.services.application.lib.application_helpers import (
    missing_admin_console_settings_scope_finding,
)

DEFAULT_THRESHOLD_MINUTES = 15


class application_admin_console_session_idle_timeout_15min(Check):
    """STIG V-273187 / OKTA-APP-000025.

    The Okta Admin Console first-party app must set its
    `Maximum app session idle time` to 15 minutes (or less) so privileged
    administrator sessions terminate on inactivity. Threshold override:
    `okta_admin_console_idle_timeout_max_minutes` in the audit config.
    """

    def execute(self) -> list[CheckReportOkta]:
        audit_config = application_client.audit_config or {}
        threshold = audit_config.get(
            "okta_admin_console_idle_timeout_max_minutes",
            DEFAULT_THRESHOLD_MINUTES,
        )
        org_domain = application_client.provider.identity.org_domain

        missing_scope = application_client.missing_scope.get(
            "admin_console_app_settings"
        )
        if missing_scope:
            return [
                missing_admin_console_settings_scope_finding(
                    self.metadata(), org_domain, missing_scope
                )
            ]

        settings = application_client.admin_console_app_settings
        if settings is None:
            placeholder = AdminConsoleAppSettings()
            report = CheckReportOkta(
                metadata=self.metadata(), resource=placeholder, org_domain=org_domain
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Could not retrieve the Okta Admin Console first-party app "
                "settings. Okta restricts `GET /api/v1/first-party-app-settings/"
                "admin-console` to the Super Administrator role; every other "
                "role — including Read-Only Administrator — receives "
                "`403 E0000006`. Assign Super Administrator to the service "
                f"app to evaluate this check. STIG V-273187 requires the "
                f"`Maximum app session idle time` to be set to {threshold} "
                "minutes or less."
            )
            return [report]

        report = CheckReportOkta(
            metadata=self.metadata(), resource=settings, org_domain=org_domain
        )
        idle = settings.session_idle_timeout_minutes
        if idle is None:
            report.status = "FAIL"
            report.status_extended = (
                "The Okta Admin Console first-party app does not define a "
                "`Maximum app session idle time`. STIG V-273187 requires "
                f"this value to be {threshold} minutes or less."
            )
        elif idle <= threshold:
            report.status = "PASS"
            report.status_extended = (
                "The Okta Admin Console first-party app sets the maximum "
                f"app session idle time to {idle} minutes, meeting the "
                f"configured threshold of {threshold} minutes."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "The Okta Admin Console first-party app sets the maximum "
                f"app session idle time to {idle} minutes, exceeding the "
                f"configured threshold of {threshold} minutes."
            )
        return [report]
