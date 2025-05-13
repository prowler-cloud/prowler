from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antispam_outbound_policy_configured(Check):
    """
    Check if the outbound spam policy is established and properly configured in the Defender service.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if an outbound spam policy is established and properly configured.

        This method checks the Defender outbound spam policies to ensure they are configured
        according to best practices.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        if defender_client.outbound_spam_policies:
            # Only Default Defender Outbound Spam Policy
            if not defender_client.outbound_spam_rules:
                # Get the only policy in the dictionary
                policy = next(iter(defender_client.outbound_spam_policies.values()))

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.name,
                    resource_id=policy.name,
                )

                if self._is_policy_properly_configured(policy):
                    # Case 1: Default policy exists and is properly configured
                    report.status = "PASS"
                    report.status_extended = f"{policy.name} is the only policy and it's properly configured in the default Defender Outbound Spam Policy."
                else:
                    # Case 5: Default policy exists but is not properly configured
                    report.status = "FAIL"
                    report.status_extended = f"{policy.name} is the only policy and it's not properly configured in the default Defender Outbound Spam Policy."
                findings.append(report)

            # Multiple Defender Outbound Spam Policies
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
                        if not self._is_policy_properly_configured(policy):
                            # Case 4: Default policy is not properly configured and there are other policies
                            report.status = "FAIL"
                            report.status_extended = f"{policy_name} is not properly configured in the default Defender Outbound Spam Policy, but could be overridden by another well-configured Custom Policy."
                            findings.append(report)
                        else:
                            # Case 2: Default policy is properly configured and there are other policies
                            report.status = "PASS"
                            report.status_extended = f"{policy_name} is properly configured in the default Defender Outbound Spam Policy, but could be overridden by another bad-configured Custom Policy."
                            default_policy_well_configured = True
                            findings.append(report)
                    else:
                        if not self._is_policy_properly_configured(policy):
                            included_resources = []

                            if defender_client.outbound_spam_rules[policy.name].users:
                                included_resources.append(
                                    f"users: {', '.join(defender_client.outbound_spam_rules[policy.name].users)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].groups:
                                included_resources.append(
                                    f"groups: {', '.join(defender_client.outbound_spam_rules[policy.name].groups)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].domains:
                                included_resources.append(
                                    f"domains: {', '.join(defender_client.outbound_spam_rules[policy.name].domains)}"
                                )

                            included_resources_str = "; ".join(included_resources)

                            # Case 3: Default policy is properly configured but other custom policies are not
                            if default_policy_well_configured:
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy {policy_name} is not properly configured and includes {included_resources_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "However, the default policy is properly configured, so entities not included by this custom policy could be correctly protected."
                                )
                                findings.append(report)
                            # Case 5: Default policy is not properly configured and other custom policies are not
                            else:
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy {policy_name} is not properly configured and includes {included_resources_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "Also, the default policy is not properly configured, so entities not included by this custom policy could not be correctly protected."
                                )
                                findings.append(report)
                        else:
                            included_resources = []

                            if defender_client.outbound_spam_rules[policy.name].users:
                                included_resources.append(
                                    f"users: {', '.join(defender_client.outbound_spam_rules[policy.name].users)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].groups:
                                included_resources.append(
                                    f"groups: {', '.join(defender_client.outbound_spam_rules[policy.name].groups)}"
                                )
                            if defender_client.outbound_spam_rules[policy.name].domains:
                                included_resources.append(
                                    f"domains: {', '.join(defender_client.outbound_spam_rules[policy.name].domains)}"
                                )

                            included_resources_str = "; ".join(included_resources)

                            # Case 2: Default policy is properly configured and other custom policies are too
                            if default_policy_well_configured:
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy {policy_name} is properly configured and includes {included_resources_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "Also, the default policy is properly configured, so entities not included by this custom policy could still be correctly protected."
                                )
                                findings.append(report)
                            # Case 6: Default policy is not properly configured but other custom policies are
                            else:
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Outbound Spam policy {policy_name} is properly configured and includes {included_resources_str}, "
                                    f"with priority {defender_client.outbound_spam_rules[policy.name].priority} (0 is the highest). "
                                    "However, the default policy is not properly configured, so entities not included by this custom policy could not be correctly protected."
                                )
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
