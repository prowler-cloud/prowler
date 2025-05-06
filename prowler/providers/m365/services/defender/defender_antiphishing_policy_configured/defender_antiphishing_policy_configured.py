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

        # Only Default Defender Anti-Phishing Policy
        if not defender_client.antiphising_rules:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Default Defender Anti-Phishing Policy",
                resource_id="defaultDefenderAntiPhishingPolicy",
            )

            if self._is_policy_properly_configured(
                defender_client.antiphishing_policies[0]
            ):
                # Case 1: Default policy exists and is properly configured
                report.status = "PASS"
                report.status_extended = "Anti-phishing policy is properly configured in the default Defender Anti-Phishing Policy."
            else:
                # Case 5: Default policy exists but is not properly configured
                report.status = "FAIL"
                report.status_extended = "Anti-phishing policy is not properly configured in the default Defender Anti-Phishing Policy."
            findings.append(report)

        # Multiple Defender Anti-Phishing Policies
        else:
            misconfigured_policies = []
            report = None

            for policy_name, policy in defender_client.antiphishing_policies.items():
                if policy.default:
                    if not self._is_policy_properly_configured(policy):
                        # Case 4: Default policy is not properly configured (potential false positive)
                        report = CheckReportM365(
                            metadata=self.metadata(),
                            resource={},
                            resource_name="Default Defender Anti-Phishing Policy",
                            resource_id="defaultDefenderAntiPhishingPolicy",
                        )
                        report.status = "FAIL"
                        report.status_extended = "Anti-phishing policy is not properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another policy which is out of Prowler's scope."
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
                    resource_name="Defender Anti-Phishing Policies",
                    resource_id="defenderAntiPhishingPolicies",
                )
                report.status = "FAIL"
                report.status_extended = f"Anti-phishing policy is properly configured in default Defender Anti-Phishing Policy but not in the following Defender Anti-Phishing Policies that may override it: {', '.join(misconfigured_policies)}."
                findings.append(report)
            elif not report:
                # Case 2: Default policy is properly configured and all other policies are too
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name="Defender Anti-Phishing Policies",
                    resource_id="defenderAntiPhishingPolicies",
                )
                report.status = "PASS"
                report.status_extended = "Anti-phishing policy is properly configured in all Defender Anti-Phishing Policies."
                findings.append(report)

        return findings

    def _is_policy_properly_configured(self, policy) -> bool:
        """
        Check if a policy is properly configured according to best practices.

        Args:
            policy: The anti-phishing policy to check.

        Returns:
            bool: True if the policy is properly configured, False otherwise.
        """
        return (
            (
                policy.default
                or defender_client.antiphising_rules[policy.name].state.lower()
                == "enabled"
            )
            and policy.spoof_intelligence
            and policy.spoof_intelligence_action.lower() == "quarantine"
            and policy.dmarc_reject_action.lower() == "quarantine"
            and policy.dmarc_quarantine_action.lower() == "quarantine"
            and policy.safety_tips
            and policy.unauthenticated_sender_action
            and policy.show_tag
            and policy.honor_dmarc_policy
        )
