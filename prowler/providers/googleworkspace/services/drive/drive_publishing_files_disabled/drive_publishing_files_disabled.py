from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.drive.drive_client import drive_client


class drive_publishing_files_disabled(Check):
    """Check that publishing Drive files to the web is disabled

    This check verifies that the domain-level Drive and Docs policy prevents
    users from publishing files to the web or making them visible to anyone
    with the link, blocking unintended public exposure of organizational
    content. The publishing option only exists when sharing outside of the
    organization is ON: with allowlisted domains or sharing OFF, Google hides
    it and nothing can be made visible to anyone with the link, whatever
    value the API still stores for the flag.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if drive_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=drive_client.policies,
                resource_id="drivePolicies",
                resource_name="Drive Policies",
                customer_id=drive_client.provider.identity.customer_id,
            )

            allow_publishing = drive_client.policies.allow_publishing_files
            sharing_mode = drive_client.policies.external_sharing_mode

            if sharing_mode == "ALLOWLISTED_DOMAINS":
                report.status = "PASS"
                report.status_extended = (
                    f"Publishing files to the web is not possible in domain "
                    f"{drive_client.provider.identity.domain}: sharing outside of "
                    f"the organization is limited to allowlisted domains."
                )
            elif sharing_mode == "DISALLOWED":
                report.status = "PASS"
                report.status_extended = (
                    f"Publishing files to the web is not possible in domain "
                    f"{drive_client.provider.identity.domain}: sharing outside of "
                    f"the organization is off."
                )
            elif allow_publishing is False:
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
