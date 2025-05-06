from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_antispam_policy_inbound_no_allowed_domains(Check):
    """
    Check if the inbound anti-spam policies do not contain allowed domains in Microsoft 365 Defender.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if inbound anti-spam policies do not contain allowed domains.

        This method checks each inbound anti-spam policy to determine if the AllowedSenderDomains
        list is empty or undefined.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        if defender_client.inbound_spam_policies:
            # Only Default Defender Inbound Spam Policy exists
            default_policy = defender_client.inbound_spam_policies[0]
            if not defender_client.inbound_spam_rules:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=default_policy,
                    resource_name=default_policy.name,
                    resource_id="defaultDefenderInboundSpamPolicy",
                )

                if self._has_no_allowed_domains(default_policy):
                    # Case 1: Default policy exists and has no allowed domains
                    report.status = "PASS"
                    report.status_extended = "Inbound anti-spam policy does not contain allowed domains in the default Defender Inbound Spam Policy (no other policies exist)."
                else:
                    # Case 5: Default policy exists but contains allowed domains
                    report.status = "FAIL"
                    report.status_extended = f"Inbound anti-spam policy contains allowed domains in the default Defender Inbound Spam Policy (no other policies exist): {defender_client.inbound_spam_policies[0].allowed_sender_domains}."
                findings.append(report)

            # Multiple Defender Inbound Spam Policies exist
            else:
                allowed_domains_policies = []
                report = None

                for policy in defender_client.inbound_spam_policies:
                    if policy.default:
                        if not self._has_no_allowed_domains(policy):
                            # Case 4: Default policy contains allowed domains (potential false positive if another policy overrides it)
                            report = CheckReportM365(
                                metadata=self.metadata(),
                                resource=policy,
                                resource_name=policy.name,
                                resource_id="defaultDefenderInboundSpamPolicy",
                            )
                            report.status = "FAIL"
                            report.status_extended = f"Inbound anti-spam policy contains allowed domains in the default Defender Inbound Spam Policy, but could be overridden by another policy which is out of Prowler's scope: {policy.allowed_sender_domains}."
                            findings.append(report)
                            break
                    else:
                        if not self._has_no_allowed_domains(policy):
                            allowed_domains_policies.append(policy.identity)

                if allowed_domains_policies:
                    # Case 3: Default policy has no allowed domains but some other policies do
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={},
                        resource_name="Defender Inbound Spam Policies",
                        resource_id="defenderInboundSpamPolicies",
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Inbound anti-spam policy does not contain allowed domains in default Defender Inbound Spam Policy but does in the following Defender Inbound Spam Policies that may override it: {', '.join(allowed_domains_policies)}."
                    findings.append(report)
                elif not report:
                    # Case 2: Default policy has no allowed domains and all other policies do too
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={},
                        resource_name="Defender Inbound Spam Policies",
                        resource_id="defenderInboundSpamPolicies",
                    )
                    report.status = "PASS"
                    report.status_extended = "Inbound anti-spam policy does not contain allowed domains in all Defender Inbound Spam Policies."
                    findings.append(report)

        return findings

    def _has_no_allowed_domains(self, policy) -> bool:
        """
        Check if the policy has no allowed domains.

        Args:
            policy: The inbound spam policy to check.

        Returns:
            bool: True if the policy has no allowed domains, False otherwise.
        """
        return (
            policy.default
            or defender_client.inbound_spam_rules[policy.identity].state.lower()
            == "enabled"
        ) and not policy.allowed_sender_domains
