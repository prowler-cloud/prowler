from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.calendar.calendar_client import (
    calendar_client,
)


class calendar_external_sharing_primary_calendar(Check):
    """Check that external sharing for primary calendars is restricted to free/busy only

    This check verifies that the domain-level policy for primary calendar external
    sharing is set to share only free/busy information, preventing exposure of
    event details to external users.
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

            sharing = calendar_client.policies.primary_calendar_external_sharing

            if sharing == "EXTERNAL_FREE_BUSY_ONLY":
                report.status = "PASS"
                report.status_extended = (
                    f"Primary calendar external sharing in domain "
                    f"{calendar_client.provider.identity.domain} is restricted to "
                    f"free/busy information only."
                )
            elif sharing is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Primary calendar external sharing uses Google's secure default "
                    f"configuration (free/busy only) "
                    f"in domain {calendar_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Primary calendar external sharing in domain "
                    f"{calendar_client.provider.identity.domain} is set to {sharing}. "
                    f"External sharing should be restricted to free/busy information only."
                )

            findings.append(report)

        return findings
