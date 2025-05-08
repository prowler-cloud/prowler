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
                policy = next(iter(defender_client.outbound_spam_policies.values()))

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.name,
                    resource_id=policy.name,
                )

                if self._is_forwarding_disabled(policy):
                    # Case 1: Default policy exists and has forwarding disabled
                    report.status = "PASS"
                    report.status_extended = f"{policy.name} is the only policy and mail forwarding is disabled."
                else:
                    # Case 5: Default policy exists but allows forwarding
                    report.status = "FAIL"
                    report.status_extended = f"{policy.name} is the only policy and mail forwarding is allowed."
                findings.append(report)

            # Multiple Defender Outbound Spam Policies exist
            else:
                default_policy_well_configured = False

                for (
                    policy_name,
                    policy,
                ) in defender_client.outbound_spam_policies.items():
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource=policy,
                        resource_name=policy_name,
                        resource_id=policy_name,
                    )

                    if policy.default:
                        if not self._is_forwarding_disabled(policy):
                            # Case 4: Default policy allows forwarding and there are other policies
                            report.status = "FAIL"
                            report.status_extended = (
                                f"{policy_name} is the default policy and mail forwarding is allowed, "
                                "but it could be overridden by another well-configured Custom Policy."
                            )
                            findings.append(report)
                        else:
                            # Case 2: Default policy disables forwarding and there are other policies
                            report.status = "PASS"
                            report.status_extended = (
                                f"{policy_name} is the default policy and mail forwarding is disabled, "
                                "but it could be overridden by another misconfigured Custom Policy."
                            )
                            default_policy_well_configured = True
                            findings.append(report)
                    else:
                        if not self._is_forwarding_disabled(policy):
                            affected_entities = []

                            if defender_client.outbound_spam_rules[policy.name].users:
                                affected_entities.append(
                                    f"users: {', '.join(defender_client.outbound_spam_rules[policy.name].users)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].groups:
                                affected_entities.append(
                                    f"groups: {', '.join(defender_client.outbound_spam_rules[policy.name].groups)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].domains:
                                affected_entities.append(
                                    f"domains: {', '.join(defender_client.outbound_spam_rules[policy.name].domains)}"
                                )

                            affected_str = "; ".join(affected_entities)

                            if default_policy_well_configured:
                                # Case 3: Default policy disables forwarding but custom one doesn't
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy '{policy_name}' allows mail forwarding and affects {affected_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "However, the default policy disables mail forwarding, so entities not affected by this custom policy could be correctly protected."
                                )
                                findings.append(report)
                            else:
                                # Case 5: Neither default nor custom policies disable forwarding
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy '{policy_name}' allows mail forwarding and affects {affected_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "Also, the default policy allows mail forwarding, so entities not affected by this custom policy could not be correctly protected."
                                )
                                findings.append(report)
                        else:
                            affected_entities = []

                            if defender_client.outbound_spam_rules[policy.name].users:
                                affected_entities.append(
                                    f"users: {', '.join(defender_client.outbound_spam_rules[policy.name].users)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].groups:
                                affected_entities.append(
                                    f"groups: {', '.join(defender_client.outbound_spam_rules[policy.name].groups)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].domains:
                                affected_entities.append(
                                    f"domains: {', '.join(defender_client.outbound_spam_rules[policy.name].domains)}"
                                )

                            affected_str = "; ".join(affected_entities)

                            if default_policy_well_configured:
                                # Case 2: Both default and custom policies disable forwarding
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy '{policy_name}' disables mail forwarding and affects {affected_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "Also, the default policy disables mail forwarding, so entities not affected by this custom policy could still be correctly protected."
                                )
                                findings.append(report)
                            else:
                                # Case 6: Default policy allows forwarding, custom policy disables it
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy '{policy_name}' disables mail forwarding and affects {affected_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "However, the default policy allows mail forwarding, so entities not affected by this custom policy could not be correctly protected."
                                )
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
