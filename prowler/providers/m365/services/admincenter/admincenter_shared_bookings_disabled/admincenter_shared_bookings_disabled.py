from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_shared_bookings_disabled(Check):
    """Check if Microsoft Bookings (Shared Bookings) is disabled.

    Bookings is considered disabled and compliant when either it is turned off at the
    tenant level (OrganizationConfig BookingsEnabled) or the default OWA mailbox
    policy prevents creation of Bookings mailboxes (BookingsMailboxCreationEnabled).

    - PASS: Bookings is disabled at the tenant level or in the default OWA mailbox
      policy.
    - FAIL: Bookings is enabled at the tenant level and allowed by the default OWA
      mailbox policy.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Shared Bookings.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = admincenter_client.organization_config
        if not organization_config:
            return findings

        default_policy = next(
            (
                policy
                for policy in admincenter_client.mailbox_policies
                if policy and policy.is_default
            ),
            None,
        )

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=organization_config,
            resource_name=organization_config.name,
            resource_id=organization_config.guid,
        )
        report.status = "FAIL"
        report.status_extended = (
            "Shared Bookings is enabled at the tenant level and in the default OWA "
            "mailbox policy."
        )

        tenant_disabled = not organization_config.bookings_enabled
        policy_disabled = bool(
            default_policy and not default_policy.bookings_mailbox_creation_enabled
        )

        if tenant_disabled or policy_disabled:
            report.status = "PASS"
            if tenant_disabled:
                report.status_extended = (
                    "Shared Bookings is disabled at the tenant level."
                )
            else:
                report.status_extended = (
                    "Shared Bookings is disabled in the default OWA mailbox policy."
                )

        findings.append(report)
        return findings
