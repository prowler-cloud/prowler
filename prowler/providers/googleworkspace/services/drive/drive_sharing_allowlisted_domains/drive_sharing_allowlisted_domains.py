from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_sharing_allowlisted_domains(Check):
    """Check that document sharing is restricted to allowlisted domains

    This check verifies that the domain-level Drive and Docs policy restricts
    external sharing to a list of explicitly allowlisted domains, blocking
    sharing with arbitrary external recipients.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.domain_resource,
            )

            mode = drive_client.policies.external_sharing_mode

            if mode == "ALLOWLISTED_DOMAINS":
                report.status = "PASS"
                report.status_extended = (
                    f"Drive and Docs external sharing in domain "
                    f"{drive_client.provider.identity.domain} is restricted to "
                    f"allowlisted domains."
                )
            else:
                report.status = "FAIL"
                if mode is None:
                    report.status_extended = (
                        f"Drive and Docs external sharing mode is not explicitly "
                        f"configured in domain {drive_client.provider.identity.domain}. "
                        f"Sharing should be restricted to allowlisted domains."
                    )
                else:
                    report.status_extended = (
                        f"Drive and Docs external sharing in domain "
                        f"{drive_client.provider.identity.domain} is set to {mode}. "
                        f"Sharing should be restricted to allowlisted domains."
                    )

            findings.append(report)

        return findings
