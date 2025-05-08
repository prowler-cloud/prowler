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
            if not defender_client.inbound_spam_rules:
                policy = defender_client.inbound_spam_policies[0]

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.identity,
                    resource_id=policy.identity,
                )

                if self._has_no_allowed_domains(policy):
                    # Case 1: Default policy exists and has no allowed domains
                    report.status = "PASS"
                    report.status_extended = f"{policy.identity} is the only policy and it does not contain allowed domains."
                else:
                    # Case 5: Default policy exists but contains allowed domains
                    report.status = "FAIL"
                    report.status_extended = f"{policy.identity} is the only policy and it contains allowed domains: {', '.join(policy.allowed_sender_domains)}."
                findings.append(report)

            # Multiple Defender Inbound Spam Policies exist
            else:
                default_policy_well_configured = False

                for policy in defender_client.inbound_spam_policies:
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource=policy,
                        resource_name=policy.identity,
                        resource_id=policy.identity,
                    )

                    if policy.default:
                        if not self._has_no_allowed_domains(policy):
                            # Case 4: Default policy contains allowed domains
                            report.status = "FAIL"
                            report.status_extended = (
                                f"{policy.identity} is the default policy and it contains allowed domains: {', '.join(policy.allowed_sender_domains)}, "
                                "but it could be overridden by another well-configured Custom Policy."
                            )
                            findings.append(report)
                        else:
                            # Case 2: Default policy has no allowed domains and there are other policies
                            report.status = "PASS"
                            report.status_extended = (
                                f"{policy.identity} is the default policy and it does not contain allowed domains, "
                                "but it could be overridden by another misconfigured Custom Policy."
                            )
                            default_policy_well_configured = True
                            findings.append(report)
                    else:
                        if not self._has_no_allowed_domains(policy):
                            affected_entities = []

                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].users:
                                affected_entities.append(
                                    f"users: {', '.join(defender_client.inbound_spam_rules[policy.identity].users)}"
                                )
                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].groups:
                                affected_entities.append(
                                    f"groups: {', '.join(defender_client.inbound_spam_rules[policy.identity].groups)}"
                                )
                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].domains:
                                affected_entities.append(
                                    f"domains: {', '.join(defender_client.inbound_spam_rules[policy.identity].domains)}"
                                )

                            affected_str = "; ".join(affected_entities)
                            priority = defender_client.inbound_spam_rules[
                                policy.identity
                            ].priority

                            if default_policy_well_configured:
                                # Case 3: Default policy has no allowed domains but custom one does
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Inbound Spam policy '{policy.identity}' contains allowed domains and affects {affected_str}, "
                                    f"with priority {priority} (0 is the highest). However, the default policy does not contain allowed domains, "
                                    "so entities not affected by this custom policy could be correctly protected."
                                )
                            else:
                                # Case 5: Neither default nor custom policies are correctly configured
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Inbound Spam policy '{policy.identity}' contains allowed domains and affects {affected_str}, "
                                    f"with priority {priority} (0 is the highest). Also, the default policy contains allowed domains, "
                                    "so entities not affected by this custom policy could not be correctly protected."
                                )
                            findings.append(report)
                        else:
                            affected_entities = []

                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].users:
                                affected_entities.append(
                                    f"users: {', '.join(defender_client.inbound_spam_rules[policy.identity].users)}"
                                )
                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].groups:
                                affected_entities.append(
                                    f"groups: {', '.join(defender_client.inbound_spam_rules[policy.identity].groups)}"
                                )
                            if defender_client.inbound_spam_rules[
                                policy.identity
                            ].domains:
                                affected_entities.append(
                                    f"domains: {', '.join(defender_client.inbound_spam_rules[policy.identity].domains)}"
                                )

                            affected_str = "; ".join(affected_entities)
                            priority = defender_client.inbound_spam_rules[
                                policy.identity
                            ].priority

                            if default_policy_well_configured:
                                # Case 2: Both default and custom policies do not contain allowed domains
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Inbound Spam policy '{policy.identity}' does not contain allowed domains and affects {affected_str}, "
                                    f"with priority {priority} (0 is the highest). Also, the default policy does not contain allowed domains, "
                                    "so entities not affected by this custom policy could still be correctly protected."
                                )
                            else:
                                # Case 6: Default policy contains allowed domains, custom policy does not
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Inbound Spam policy '{policy.identity}' does not contain allowed domains and affects {affected_str}, "
                                    f"with priority {priority} (0 is the highest). However, the default policy contains allowed domains, "
                                    "so entities not affected by this custom policy could not be correctly protected."
                                )
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
