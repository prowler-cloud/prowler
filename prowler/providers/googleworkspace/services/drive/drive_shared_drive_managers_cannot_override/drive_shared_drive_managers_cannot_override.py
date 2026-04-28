from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_shared_drive_managers_cannot_override(Check):
    """Check that shared drive managers cannot override shared drive settings

    This check verifies that the domain-level Drive and Docs policy prevents
    members with manager access from overriding the shared drive settings
    configured by administrators, ensuring that security controls cannot be
    relaxed at the shared drive level.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.domain_resource,
            )

            allow_override = drive_client.policies.allow_managers_to_override_settings

            if allow_override is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Shared drive managers in domain "
                    f"{drive_client.provider.identity.domain} cannot override "
                    f"shared drive settings."
                )
            else:
                report.status = "FAIL"
                if allow_override is None:
                    report.status_extended = (
                        f"Manager override of shared drive settings is not "
                        f"explicitly configured in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Managers should not be allowed to override shared drive settings."
                    )
                else:
                    report.status_extended = (
                        f"Shared drive managers in domain "
                        f"{drive_client.provider.identity.domain} are allowed to "
                        f"override shared drive settings. "
                        f"Managers should not be allowed to override shared drive settings."
                    )

            findings.append(report)

        return findings
