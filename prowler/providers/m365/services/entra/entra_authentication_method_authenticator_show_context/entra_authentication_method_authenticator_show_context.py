from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_authentication_method_authenticator_show_context(Check):
    """Check if Microsoft Authenticator shows application name and geographic location.

    The Microsoft Authenticator method should be enabled with the
    ``displayAppInformationRequiredState`` and
    ``displayLocationInformationRequiredState`` feature settings enabled, so users see
    the app name and sign-in location context in push and passwordless notifications.

    - PASS: Both application name and geographic location context are shown.
    - FAIL: Application name and/or geographic location context is not shown.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = entra_client.authentication_methods_policy_settings
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="Microsoft Authenticator Method",
            resource_id="microsoftAuthenticator",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Microsoft Authenticator does not show both application name and "
            "geographic location in notifications."
        )

        if (
            settings.authenticator_display_app_information_state == "enabled"
            and settings.authenticator_display_location_information_state == "enabled"
        ):
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Authenticator shows application name and geographic "
                "location in notifications."
            )

        findings.append(report)
        return findings
