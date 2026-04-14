from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_publishing_files_disabled(Check):
    """Check that publishing Drive files to the web is disabled

    This check verifies that the domain-level Drive and Docs policy prevents
    users from publishing files to the web or making them visible to anyone
    with the link, blocking unintended public exposure of organizational
    content.
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

            allow_publishing = drive_client.policies.allow_publishing_files

            if allow_publishing is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Publishing files to the web is disabled in domain "
                    f"{drive_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if allow_publishing is None:
                    report.status_extended = (
                        f"Publishing files to the web is not explicitly configured "
                        f"in domain {drive_client.provider.identity.domain}. "
                        f"Users should not be able to publish files to the web or make them public."
                    )
                else:
                    report.status_extended = (
                        f"Publishing files to the web is enabled in domain "
                        f"{drive_client.provider.identity.domain}. "
                        f"Users should not be able to publish files to the web or make them public."
                    )

            findings.append(report)

        return findings
