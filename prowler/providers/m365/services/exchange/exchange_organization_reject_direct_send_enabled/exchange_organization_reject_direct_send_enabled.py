from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_organization_reject_direct_send_enabled(Check):
    """Check if Direct Send is rejected in the Exchange Online organization.

    Direct Send lets on-premises devices, applications, or third-party services
    send email to the tenant's hosted mailboxes using an accepted domain without
    authentication. Rejecting Direct Send reduces the risk of spoofed internal
    email.

    - PASS: RejectDirectSend is enabled for the organization.
    - FAIL: RejectDirectSend is disabled for the organization.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for the Direct Send organization setting.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = exchange_client.organization_config
        if organization_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "Direct Send is not rejected for the Exchange Online organization."
            )

            if organization_config.reject_direct_send:
                report.status = "PASS"
                report.status_extended = (
                    "Direct Send is rejected for the Exchange Online organization."
                )

            findings.append(report)

        return findings
