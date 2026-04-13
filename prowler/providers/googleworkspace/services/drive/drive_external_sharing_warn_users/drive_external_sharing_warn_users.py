from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_external_sharing_warn_users(Check):
    """Check that users are warned when sharing files outside the domain

    This check verifies that the domain-level Drive and Docs policy warns
    users when they attempt to share a file with someone outside the
    organization, reducing the risk of accidental information disclosure.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.provider.identity,
                resource_name=drive_client.provider.identity.domain,
                resource_id=drive_client.provider.identity.customer_id,
                customer_id=drive_client.provider.identity.customer_id,
                location="global",
            )

            warning_enabled = drive_client.policies.warn_for_external_sharing

            if warning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"External sharing warnings for Drive and Docs are enabled "
                    f"in domain {drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if warning_enabled is None:
                    report.status_extended = (
                        f"External sharing warnings for Drive and Docs are not "
                        f"explicitly configured in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Users should be warned when sharing files outside the organization."
                    )
                else:
                    report.status_extended = (
                        f"External sharing warnings for Drive and Docs are disabled "
                        f"in domain {drive_client.provider.identity.domain}. "
                        f"Users should be warned when sharing files outside the organization."
                    )

            findings.append(report)

        return findings
