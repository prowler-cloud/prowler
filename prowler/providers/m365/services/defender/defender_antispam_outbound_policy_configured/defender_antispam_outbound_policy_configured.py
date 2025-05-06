from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antispam_outbound_policy_configured(Check):
    """
    Check if the Exchange Online Spam Policies are configured to notify administrators
    when a sender is blocked for sending spam emails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if the Exchange Online Spam Policies notify administrators
        when a sender is blocked for sending spam emails.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # Only Default Defender Outbound Spam Policy exists
        if not defender_client.outbound_spam_rules:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Default Defender Outbound Spam Policy",
                resource_id="defaultDefenderOutboundSpamPolicy",
            )

            if self._is_policy_properly_configured(
                defender_client.outbound_spam_policies[0]
            ):
                # Case 1: Default policy exists and is properly configured
                report.status = "PASS"
                report.status_extended = "Outbound Spam Policy is properly configured in the default Defender Outbound Spam Policy (no other policies exist)."
            else:
                # Case 5: Default policy exists but is not properly configured
                report.status = "FAIL"
                report.status_extended = "Outbound Spam Policy is not properly configured in the default Defender Outbound Spam Policy (no other policies exist)."
            findings.append(report)

        # Multiple Defender Outbound Spam Policies exist
        else:
            misconfigured_policies = []
            report = None

            for policy_name, policy in defender_client.outbound_spam_policies.items():
                if policy.default:
                    if not self._is_policy_properly_configured(policy):
                        # Case 4: Default policy is not properly configured (potential false positive if another policy overrides it)
                        report = CheckReportM365(
                            metadata=self.metadata(),
                            resource={},
                            resource_name="Default Defender Outbound Spam Policy",
                            resource_id="defaultDefenderOutboundSpamPolicy",
                        )
                        report.status = "FAIL"
                        report.status_extended = "Outbound Spam Policy is not properly configured in the default Defender Outbound Spam Policy, but could be overridden by another policy which is out of Prowler's scope."
                        findings.append(report)
                        break
                else:
                    if not self._is_policy_properly_configured(policy):
                        misconfigured_policies.append(policy_name)

            if misconfigured_policies:
                # Case 3: Default policy is properly configured but some other policies are not
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name="Defender Outbound Spam Policies",
                    resource_id="defenderOutboundSpamPolicies",
                )
                report.status = "FAIL"
                report.status_extended = f"Outbound Spam Policy is properly configured in default Defender Outbound Spam Policy but not in the following Defender Outbound Spam Policies that may override it: {', '.join(misconfigured_policies)}."
                findings.append(report)
            elif not report:
                # Case 2: Default policy is properly configured and all other policies are too
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name="Defender Outbound Spam Policies",
                    resource_id="defenderOutboundSpamPolicies",
                )
                report.status = "PASS"
                report.status_extended = "Outbound Spam Policy is properly configured in all Defender Outbound Spam Policies."
                findings.append(report)

        return findings

    def _is_policy_properly_configured(self, policy) -> bool:
        """
        Check if a policy is properly configured according to best practices.

        Args:
            policy: The outbound spam policy to check.

        Returns:
            bool: True if the policy is properly configured, False otherwise.
        """
        return (
            (
                policy.default
                or defender_client.outbound_spam_rules[policy.name].state.lower()
                == "enabled"
            )
            and policy.notify_limit_exceeded
            and policy.notify_sender_blocked
            and policy.notify_limit_exceeded_addresses
            and policy.notify_sender_blocked_addresses
        )
