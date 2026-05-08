from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.gmail.gmail_client import gmail_client


class gmail_employee_name_spoofing_protection_enabled(Check):
    """Check that protection against spoofing of employee names is enabled.

    This check verifies that Gmail is configured to take action on
    emails where the sender name matches an employee name but comes
    from an external address, helping prevent social engineering attacks.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if gmail_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=gmail_client.provider.domain_resource,
            )

            enabled = gmail_client.policies.detect_employee_name_spoofing
            consequence = gmail_client.policies.employee_name_spoofing_consequence

            if enabled is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against spoofing of employee names is "
                    f"disabled in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"Enable the protection and configure a protective action."
                )
            elif consequence == "NO_ACTION":
                report.status = "FAIL"
                report.status_extended = (
                    f"Protection against spoofing of employee names is set "
                    f"to take no action in domain "
                    f"{gmail_client.provider.identity.domain}. "
                    f"A protective action should be configured."
                )
            elif consequence is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against spoofing of employee names uses "
                    f"Google's secure default configuration (enabled) "
                    f"in domain {gmail_client.provider.identity.domain}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Protection against spoofing of employee names is "
                    f"enabled with consequence '{consequence}' in domain "
                    f"{gmail_client.provider.identity.domain}."
                )

            findings.append(report)

        return findings
