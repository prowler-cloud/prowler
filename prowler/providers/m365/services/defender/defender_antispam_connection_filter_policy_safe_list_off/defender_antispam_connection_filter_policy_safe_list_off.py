from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antispam_connection_filter_policy_safe_list_off(Check):
    """
    Check if the Safe List is off in the Defender connection filter policy.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if the Safe List is off.

        This method checks the Defender connection filter policy to determine if the
        Safe List is disabled.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        policy = defender_client.connection_filter_policy
        if policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Connection Filter Policy",
                resource_id=policy.identity,
            )
            report.status = "PASS"
            report.status_extended = f"Safe List is off in the Defender connection filter policy {policy.identity}."

            if policy.enable_safe_list:
                report.status = "FAIL"
                report.status_extended = f"Safe List is on in the Defender connection filter policy {policy.identity}."

            findings.append(report)

        return findings
