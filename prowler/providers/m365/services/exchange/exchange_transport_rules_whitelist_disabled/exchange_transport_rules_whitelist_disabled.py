from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_transport_rules_whitelist_disabled(Check):
    """
    Check to ensure that no mail transport rules whitelist specific domains.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to validate that no transport rules whitelist specific domains.

        This method retrieves all transport rules from the Exchange service and evaluates
        whether any of them whitelist specific domains. A report is generated for each
        transport rule.

        Returns:
            List[CheckReportM365]: A list of findings with the status of each transport rule.
        """
        findings = []

        for rule in exchange_client.transport_rules:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=rule,
                resource_name=rule.name,
                resource_id="ExchangeTransportRule",
            )

            report.status = "PASS"
            report.status_extended = (
                f"Transport rule '{rule.name}' does not whitelist any domains."
            )

            if rule.sender_domain_is and rule.scl == -1:
                report.status = "FAIL"
                report.status_extended = f"Transport rule '{rule.name}' whitelists domains: {', '.join(rule.sender_domain_is)}."

            findings.append(report)

        return findings
