from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_access_checker_recipients_only(Check):
    """Check that Access Checker is configured to recipients only

    This check verifies that the domain-level Drive and Docs Access Checker
    setting suggests granting access only to the explicit recipients of a
    shared link, rather than expanding access to wider audiences or making
    files publicly accessible.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.domain_resource,
            )

            access_checker = drive_client.policies.access_checker_suggestions

            if access_checker == "RECIPIENTS_ONLY":
                report.status = "PASS"
                report.status_extended = (
                    f"Drive and Docs Access Checker in domain "
                    f"{drive_client.provider.identity.domain} is restricted to "
                    f"recipients only."
                )
            else:
                report.status = "FAIL"
                if access_checker is None:
                    report.status_extended = (
                        f"Drive and Docs Access Checker is not explicitly "
                        f"configured in domain {drive_client.provider.identity.domain}. "
                        f"Access Checker should be set to recipients only."
                    )
                else:
                    report.status_extended = (
                        f"Drive and Docs Access Checker in domain "
                        f"{drive_client.provider.identity.domain} is set to "
                        f"{access_checker}. Access Checker should be set to recipients only."
                    )

            findings.append(report)

        return findings
