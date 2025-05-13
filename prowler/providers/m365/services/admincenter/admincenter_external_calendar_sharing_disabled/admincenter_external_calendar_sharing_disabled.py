from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_external_calendar_sharing_disabled(Check):
    """
    Ensure that external calendar sharing is disabled for the organization.

    Disabling external calendar sharing restricts the ability for users to share their
    calendars externally in Microsoft 365. This prevents users from sending calendar
    sharing links to external recipients, reducing information exposure.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check for external calendar sharing in Microsoft 365.

        This method checks if external calendar sharing is disabled in the organization configuration.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        sharing_policy = admincenter_client.sharing_policy
        if sharing_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sharing_policy,
                resource_name=sharing_policy.name,
                resource_id=sharing_policy.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "External calendar sharing is enabled at the organization level."
            )

            if not sharing_policy.enabled:
                report.status = "PASS"
                report.status_extended = (
                    "External calendar sharing is disabled at the organization level."
                )

            findings.append(report)

        return findings
