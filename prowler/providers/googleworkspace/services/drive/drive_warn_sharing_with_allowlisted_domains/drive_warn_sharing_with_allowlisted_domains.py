from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_warn_sharing_with_allowlisted_domains(Check):
    """Check that users are warned when sharing with allowlisted domains

    This check verifies that the domain-level Drive and Docs policy warns
    users when they share files with users in allowlisted domains, providing
    an opportunity to reconsider before sharing externally even within
    permitted domains.
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

            warn_enabled = (
                drive_client.policies.warn_for_sharing_outside_allowlisted_domains
            )

            if warn_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"Users are warned when sharing files with allowlisted "
                    f"domains in domain {drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if warn_enabled is None:
                    report.status_extended = (
                        f"Warning when sharing with allowlisted domains is not "
                        f"explicitly configured in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Users should be warned when sharing files with users in allowlisted domains."
                    )
                else:
                    report.status_extended = (
                        f"Warning when sharing with allowlisted domains is disabled "
                        f"in domain {drive_client.provider.identity.domain}. "
                        f"Users should be warned when sharing files with users in allowlisted domains."
                    )

            findings.append(report)

        return findings
