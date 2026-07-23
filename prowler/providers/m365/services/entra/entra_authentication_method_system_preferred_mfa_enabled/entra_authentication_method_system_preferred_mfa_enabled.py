from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

ALL_USERS_TARGETS = {"all_users", "all users"}


class entra_authentication_method_system_preferred_mfa_enabled(Check):
    """Check if system-preferred multifactor authentication is enabled for all users.

    System-preferred MFA prompts users to sign in with the most secure method they
    have registered. Its ``systemCredentialPreferences.state`` should be enabled and
    target all users.

    - PASS: System-preferred MFA is enabled and targets all users.
    - FAIL: System-preferred MFA is disabled or does not target all users.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = entra_client.authentication_methods_policy_settings
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="System-preferred MFA",
            resource_id="systemCredentialPreferences",
        )
        report.status = "FAIL"
        report.status_extended = (
            "System-preferred multifactor authentication is not enabled for all users."
        )

        targets = {
            str(target).lower()
            for target in settings.system_preferred_mfa_include_targets
        }
        if (
            settings.system_preferred_mfa_state == "enabled"
            and targets & ALL_USERS_TARGETS
        ):
            report.status = "PASS"
            report.status_extended = (
                "System-preferred multifactor authentication is enabled for all users."
            )

        findings.append(report)
        return findings
