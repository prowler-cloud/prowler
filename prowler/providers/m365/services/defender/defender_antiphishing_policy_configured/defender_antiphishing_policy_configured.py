from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antiphishing_policy_configured(Check):
    """
    Check if an anti-phishing policy is established and properly configured in the Defender service.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if an anti-phishing policy is established and properly configured.

        This method checks the Defender anti-phishing policies to ensure they are configured
        according to best practices.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for policy_name, policy in defender_client.antiphishing_policies.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Anti-Phishing Policy",
                resource_id=policy_name,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Anti-phishing policy {policy_name} is not properly configured."
            )

            if (
                not policy.default
                and policy_name in defender_client.antiphising_rules
                and defender_client.antiphising_rules[policy_name].state.lower()
                == "enabled"
            ) or policy.default:
                if (
                    policy.spoof_intelligence
                    and policy.spoof_intelligence_action.lower() == "quarantine"
                    and policy.dmarc_reject_action.lower() == "quarantine"
                    and policy.dmarc_quarantine_action.lower() == "quarantine"
                    and policy.safety_tips
                    and policy.unauthenticated_sender_action
                    and policy.show_tag
                    and policy.honor_dmarc_policy
                ):
                    report.status = "PASS"
                    report.status_extended = f"Anti-phishing policy {policy_name} is properly configured and enabled."

            findings.append(report)

        return findings
