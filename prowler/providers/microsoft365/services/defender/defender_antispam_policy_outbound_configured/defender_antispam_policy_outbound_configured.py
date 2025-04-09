from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.defender.defender_client import (
    defender_client,
)


class defender_antispam_policy_outbound_configured(Check):
    """
    Check if the Exchange Online Spam Policies are configured to notify administrators
    when a sender is blocked for sending spam emails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the check to verify if the Exchange Online Spam Policies notify administrators
        when a sender is blocked for sending spam emails.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []
        for policy_name, policy in defender_client.outbound_spam_policies.items():
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Outbound Spam Policy",
                resource_id=policy_name,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Outbound Spam Policy '{policy_name}' is not properly configured."
            )

            if (
                not policy.default
                and policy_name in defender_client.outbound_spam_rules
                and defender_client.outbound_spam_rules[policy_name].state.lower()
                == "enabled"
            ) or policy.default:

                if (
                    policy.notify_limit_exceeded
                    and policy.notify_sender_blocked
                    and policy.notify_limit_exceeded_adresses
                    and policy.notify_sender_blocked_adresses
                ):

                    report.status = "PASS"
                    report.status_extended = f"Outbound Spam Policy '{policy_name}' is not properly configured and enabled."

            findings.append(report)

        return findings
