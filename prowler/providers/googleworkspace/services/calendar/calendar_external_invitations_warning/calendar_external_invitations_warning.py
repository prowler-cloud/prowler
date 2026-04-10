from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.calendar.calendar_client import (
    calendar_client,
)


class calendar_external_invitations_warning(Check):
    """Check that external invitation warnings are enabled for Google Calendar

    This check verifies that the domain-level policy warns users when they
    invite guests from outside the organization, reducing the risk of accidental
    information disclosure through calendar events.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if calendar_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=calendar_client.provider.identity,
                resource_name=calendar_client.provider.identity.domain,
                resource_id=calendar_client.provider.identity.customer_id,
                customer_id=calendar_client.provider.identity.customer_id,
                location="global",
            )

            warning_enabled = calendar_client.policies.external_invitations_warning

            if warning_enabled is True:
                report.status = "PASS"
                report.status_extended = (
                    f"External invitation warnings for Google Calendar are enabled "
                    f"in domain {calendar_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if warning_enabled is None:
                    report.status_extended = (
                        f"External invitation warnings for Google Calendar are not "
                        f"explicitly configured in domain "
                        f"{calendar_client.provider.identity.domain}. "
                        f"Users should be warned when inviting guests outside the organization."
                    )
                else:
                    report.status_extended = (
                        f"External invitation warnings for Google Calendar are disabled "
                        f"in domain {calendar_client.provider.identity.domain}. "
                        f"Users should be warned when inviting guests outside the organization."
                    )

            findings.append(report)

        return findings
