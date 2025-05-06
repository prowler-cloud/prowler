from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antispam_outbound_policy_forwarding_disabled(Check):
    """
    Check if the Defender Outbound Spam Policies are configured to disable mail forwarding.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if the Defender Outbound Spam Policies disable mail forwarding.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for policy_name, policy in defender_client.outbound_spam_policies.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Outbound Spam Policy",
                resource_id=policy_name,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Outbound Spam Policy {policy_name} does allow mail forwarding."
            )

            if (
                not policy.default
                and policy_name in defender_client.outbound_spam_rules
                and defender_client.outbound_spam_rules[policy_name].state.lower()
                == "enabled"
            ) or policy.default:
                if not policy.auto_forwarding_mode:
                    report.status = "PASS"
                    report.status_extended = f"Outbound Spam Policy {policy_name} does not allow mail forwarding."

            findings.append(report)

        return findings
