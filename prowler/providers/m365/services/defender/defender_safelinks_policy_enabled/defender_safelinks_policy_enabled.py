from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_safelinks_policy_enabled(Check):
    """
    Check if Safe Links policy is enabled and properly configured in Microsoft Defender for Office 365.

    This check verifies that the Safe Links policy (Priority 0 or Built-In Protection) has the
    following settings configured according to CIS Microsoft 365 Foundations Benchmark v5.0.0:

    - EnableSafeLinksForEmail = True
    - EnableSafeLinksForTeams = True
    - EnableSafeLinksForOffice = True
    - TrackClicks = True
    - AllowClickThrough = False
    - ScanUrls = True
    - EnableForInternalSenders = True
    - DeliverMessageAfterScan = True
    - DisableUrlRewrite = False

    - PASS: Safe Links policy is properly configured with all required settings.
    - FAIL: Safe Links policy is missing or not properly configured.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if Safe Links policy is properly configured.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        if defender_client.safe_links_policies:
            # Check if there are custom rules (non-built-in policies)
            if not defender_client.safe_links_rules:
                # Only Built-In Protection Policy exists
                policy = next(iter(defender_client.safe_links_policies.values()))

                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.name,
                    resource_id=policy.identity,
                )

                misconfigured_settings = self._get_misconfigured_settings(policy)

                if not misconfigured_settings:
                    report.status = "PASS"
                    report.status_extended = f"Safe Links policy {policy.name} is properly configured with all recommended settings."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Safe Links policy {policy.name} has the following misconfigured settings: {', '.join(misconfigured_settings)}."

                findings.append(report)

            # Multiple Safe Links Policies
            else:
                builtin_policy_configured = False

                for policy_name, policy in defender_client.safe_links_policies.items():
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource=policy,
                        resource_name=policy_name,
                        resource_id=policy.identity,
                    )

                    misconfigured_settings = self._get_misconfigured_settings(policy)

                    if policy.is_built_in_protection or policy.is_default:
                        if misconfigured_settings:
                            report.status = "FAIL"
                            report.status_extended = f"Built-in Safe Links policy {policy_name} has the following misconfigured settings: {', '.join(misconfigured_settings)}. Custom policies may override these settings for specific users."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Built-in Safe Links policy {policy_name} is properly configured. Custom policies may override these settings for specific users."
                            builtin_policy_configured = True
                        findings.append(report)
                    else:
                        # Custom policy
                        included_resources = self._get_included_resources(policy_name)
                        included_resources_str = (
                            "; ".join(included_resources)
                            if included_resources
                            else "unknown scope"
                        )

                        rule = defender_client.safe_links_rules.get(policy_name)
                        priority = rule.priority if rule else "unknown"

                        if misconfigured_settings:
                            if builtin_policy_configured:
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Safe Links policy {policy_name} has the following misconfigured settings: {', '.join(misconfigured_settings)}. "
                                    f"Policy includes {included_resources_str} with priority {priority} (0 is highest). "
                                    f"The built-in policy is properly configured, so entities not covered by this custom policy may still be protected."
                                )
                            else:
                                report.status = "FAIL"
                                report.status_extended = (
                                    f"Custom Safe Links policy {policy_name} has the following misconfigured settings: {', '.join(misconfigured_settings)}. "
                                    f"Policy includes {included_resources_str} with priority {priority} (0 is highest). "
                                    f"The built-in policy is also not properly configured."
                                )
                        else:
                            if builtin_policy_configured:
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Safe Links policy {policy_name} is properly configured. "
                                    f"Policy includes {included_resources_str} with priority {priority} (0 is highest). "
                                    f"The built-in policy is also properly configured."
                                )
                            else:
                                report.status = "PASS"
                                report.status_extended = (
                                    f"Custom Safe Links policy {policy_name} is properly configured. "
                                    f"Policy includes {included_resources_str} with priority {priority} (0 is highest). "
                                    f"However, the built-in policy is not properly configured, so entities not covered by this custom policy may not be protected."
                                )
                        findings.append(report)

        return findings

    def _get_misconfigured_settings(self, policy) -> list[str]:
        """
        Check which settings are not properly configured according to CIS recommendations.

        Args:
            policy: The Safe Links policy to check.

        Returns:
            list: A list of setting names that are not properly configured.
        """
        misconfigured = []

        if not policy.enable_safe_links_for_email:
            misconfigured.append("EnableSafeLinksForEmail should be True")
        if not policy.enable_safe_links_for_teams:
            misconfigured.append("EnableSafeLinksForTeams should be True")
        if not policy.enable_safe_links_for_office:
            misconfigured.append("EnableSafeLinksForOffice should be True")
        if not policy.track_clicks:
            misconfigured.append("TrackClicks should be True")
        if policy.allow_click_through:
            misconfigured.append("AllowClickThrough should be False")
        if not policy.scan_urls:
            misconfigured.append("ScanUrls should be True")
        if not policy.enable_for_internal_senders:
            misconfigured.append("EnableForInternalSenders should be True")
        if not policy.deliver_message_after_scan:
            misconfigured.append("DeliverMessageAfterScan should be True")
        if policy.disable_url_rewrite:
            misconfigured.append("DisableUrlRewrite should be False")

        return misconfigured

    def _get_included_resources(self, policy_name: str) -> list[str]:
        """
        Get the resources (users, groups, domains) included in a custom policy.

        Args:
            policy_name: The name of the policy.

        Returns:
            list: A list of strings describing the included resources.
        """
        included_resources = []

        rule = defender_client.safe_links_rules.get(policy_name)
        if rule:
            if rule.users:
                included_resources.append(f"users: {', '.join(rule.users)}")
            if rule.groups:
                included_resources.append(f"groups: {', '.join(rule.groups)}")
            if rule.domains:
                included_resources.append(f"domains: {', '.join(rule.domains)}")

        return included_resources
