from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.calendar.calendar_client import (
    calendar_client,
)


class calendar_external_sharing_secondary_calendar(Check):
    """Check that external sharing for secondary calendars is restricted to free/busy only

    This check verifies that the domain-level policy for secondary calendar external
    sharing is set to share only free/busy information, preventing exposure of
    event details in user-created calendars to external users.
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

            sharing = calendar_client.policies.secondary_calendar_external_sharing

            if sharing == "EXTERNAL_FREE_BUSY_ONLY":
                report.status = "PASS"
                report.status_extended = (
                    f"Secondary calendar external sharing in domain "
                    f"{calendar_client.provider.identity.domain} is restricted to "
                    f"free/busy information only."
                )
            else:
                report.status = "FAIL"
                if sharing is None:
                    report.status_extended = (
                        f"Secondary calendar external sharing is not explicitly configured "
                        f"in domain {calendar_client.provider.identity.domain}. "
                        f"External sharing should be restricted to free/busy information only."
                    )
                else:
                    report.status_extended = (
                        f"Secondary calendar external sharing in domain "
                        f"{calendar_client.provider.identity.domain} is set to {sharing}. "
                        f"External sharing should be restricted to free/busy information only."
                    )

            findings.append(report)

        return findings
