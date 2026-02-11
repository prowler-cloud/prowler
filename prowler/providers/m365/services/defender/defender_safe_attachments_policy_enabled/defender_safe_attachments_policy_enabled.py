from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_safe_attachments_policy_enabled(Check):
    """
    Check if Safe Attachments policy is properly configured in Microsoft Defender for Office 365.

    This check verifies that Safe Attachments policies have the following settings
    configured according to CIS Microsoft 365 Foundations Benchmark:

    - Enable = True
    - Action = Block
    - QuarantineTag = AdminOnlyAccessPolicy

    Note: The Built-in Protection Policy has fixed settings that cannot be changed
    and always provides baseline protection.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []

        if defender_client.safe_attachments_policies:
            # Only Built-in Protection Policy exists (no custom policies with rules)
            if not defender_client.safe_attachments_rules:
                policy = next(iter(defender_client.safe_attachments_policies.values()))

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.name,
                    resource_id=policy.identity,
                )

                # Case 1: Only Built-in policy exists - always PASS (fixed settings)
                report.status = "PASS"
                report.status_extended = f"{policy.name} is the only Safe Attachments policy and provides baseline protection for all users."
                findings.append(report)

            # Multiple Safe Attachments Policies (Built-in + custom policies)
            else:
                for (
                    policy_name,
                    policy,
                ) in defender_client.safe_attachments_policies.items():
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource=policy,
                        resource_name=policy_name,
                        resource_id=policy.identity,
                    )

                    if policy.is_built_in_protection:
                        # Case 2: Built-in policy with custom policies - always PASS
                        report.status = "PASS"
                        report.status_extended = (
                            f"{policy_name} provides baseline Safe Attachments protection, "
                            f"but could be overridden by a misconfigured custom policy for specific users."
                        )
                        findings.append(report)
                    else:
                        # Custom policy - check configuration
                        rule = defender_client.safe_attachments_rules.get(policy_name)
                        if not rule:
                            continue

                        included_resources = []
                        if rule.users:
                            included_resources.append(f"users: {', '.join(rule.users)}")
                        if rule.groups:
                            included_resources.append(
                                f"groups: {', '.join(rule.groups)}"
                            )
                        if rule.domains:
                            included_resources.append(
                                f"domains: {', '.join(rule.domains)}"
                            )
                        # If no users, groups, or domains specified, the policy applies to all recipients
                        included_resources_str = (
                            "; ".join(included_resources)
                            if included_resources
                            else "all users"
                        )

                        if self._is_policy_properly_configured(policy, rule):
                            # Case 2: Custom policy is properly configured
                            report.status = "PASS"
                            report.status_extended = (
                                f"Custom Safe Attachments policy {policy_name} is properly configured and includes {included_resources_str}, "
                                f"with priority {rule.priority} (0 is the highest)."
                            )
                        else:
                            # Case 3: Custom policy is not properly configured
                            report.status = "FAIL"
                            report.status_extended = (
                                f"Custom Safe Attachments policy {policy_name} is not properly configured and includes {included_resources_str}, "
                                f"with priority {rule.priority} (0 is the highest)."
                            )
                        findings.append(report)

        return findings

    def _is_policy_properly_configured(self, policy, rule) -> bool:
        """Check if a custom policy is properly configured according to CIS recommendations."""
        return (
            rule.state.lower() == "enabled"
            and policy.enable
            and policy.action == "Block"
            and policy.quarantine_tag == "AdminOnlyAccessPolicy"
        )
