from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.defender.defender_client import (
    defender_client,
)


class defender_connection_filter_ip_allow_list_not_used(Check):
    """
    Check if the IP Allow List is not used in the Defender connection filter policy.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the check to verify if the IP Allow List is not used.

        This method checks the Defender connection filter policy to determine if the
        IP Allow List is empty or undefined.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []
        policy = defender_client.connection_filter_policy
        if policy:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Connection Filter Policy",
                resource_id=policy.identity,
            )
            report.status = "PASS"
            report.status_extended = f"IP Allow List is not used in the Defender connection filter policy {policy.identity}."

            if policy.ip_allow_list:
                report.status = "FAIL"
                report.status_extended = f"IP Allow List is used in the Defender connection filter policy {policy.identity} with IPs: {policy.ip_allow_list}."

            findings.append(report)

        return findings
