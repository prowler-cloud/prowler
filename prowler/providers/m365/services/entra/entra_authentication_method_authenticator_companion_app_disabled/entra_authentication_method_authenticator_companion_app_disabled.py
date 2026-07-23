from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_authentication_method_authenticator_companion_app_disabled(Check):
    """Check if Microsoft Authenticator on companion applications is disabled.

    Authenticator Lite embeds a subset of Microsoft Authenticator functionality into
    companion applications such as Outlook mobile. The
    ``featureSettings.companionAppAllowedState`` should be disabled so MFA is bound to
    the full Authenticator app.

    - PASS: Microsoft Authenticator on companion applications is disabled.
    - FAIL: Microsoft Authenticator on companion applications is not disabled.
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
            "Microsoft Authenticator on companion applications is not disabled."
        )

        if settings.authenticator_companion_app_state == "disabled":
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Authenticator on companion applications is disabled."
            )

        findings.append(report)
        return findings
