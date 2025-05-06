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

        if defender_client.outbound_spam_policies:
            # Only Default Defender Outbound Spam Policy exists
            if not defender_client.outbound_spam_rules:
                # Get the only policy in the dictionary
                policy = next(iter(defender_client.outbound_spam_policies.values()))

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.name,
                    resource_id="defaultDefenderOutboundSpamPolicy",
                )

                if self._is_forwarding_disabled(policy):
                    # Case 1: Default policy exists and has forwarding disabled
                    report.status = "PASS"
                    report.status_extended = "Mail forwarding is disabled in the default Defender Outbound Spam Policy (no other policies exist)."
                else:
                    # Case 5: Default policy exists but allows forwarding
                    report.status = "FAIL"
                    report.status_extended = "Mail forwarding is allowed in the default Defender Outbound Spam Policy (no other policies exist)."
                findings.append(report)

            # Multiple Defender Outbound Spam Policies exist
            else:
                forwarding_enabled_policies = []
                report = None

                for (
                    policy_name,
                    policy,
                ) in defender_client.outbound_spam_policies.items():
                    if policy.default:
                        if not self._is_forwarding_disabled(policy):
                            # Case 4: Default policy allows forwarding (potential false positive if another policy overrides it)
                            report = CheckReportM365(
                                metadata=self.metadata(),
                                resource=policy,
                                resource_name=policy.name,
                                resource_id="defaultDefenderOutboundSpamPolicy",
                            )
                            report.status = "FAIL"
                            report.status_extended = "Mail forwarding is allowed in the default Defender Outbound Spam Policy, but could be overridden by another policy which is out of Prowler's scope."
                            findings.append(report)
                            break
                    else:
                        if not self._is_forwarding_disabled(policy):
                            forwarding_enabled_policies.append(policy_name)

                if forwarding_enabled_policies:
                    # Case 3: Default policy has forwarding disabled but some other policies allow it
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={},
                        resource_name="Defender Outbound Spam Policies",
                        resource_id="defenderOutboundSpamPolicies",
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Mail forwarding is disabled in default Defender Outbound Spam Policy but allowed in the following Defender Outbound Spam Policies that may override it: {', '.join(forwarding_enabled_policies)}."
                    findings.append(report)
                elif not report:
                    # Case 2: Default policy has forwarding disabled and all other policies do too
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={},
                        resource_name="Defender Outbound Spam Policies",
                        resource_id="defenderOutboundSpamPolicies",
                    )
                    report.status = "PASS"
                    report.status_extended = "Mail forwarding is disabled in all Defender Outbound Spam Policies."
                    findings.append(report)

        return findings

    def _is_forwarding_disabled(self, policy) -> bool:
        """
        Check if mail forwarding is disabled in the policy.

        Args:
            policy: The outbound spam policy to check.

        Returns:
            bool: True if mail forwarding is disabled, False otherwise.
        """
        return (
            policy.default
            or defender_client.outbound_spam_rules[policy.name].state.lower()
            == "enabled"
        ) and not policy.auto_forwarding_mode
