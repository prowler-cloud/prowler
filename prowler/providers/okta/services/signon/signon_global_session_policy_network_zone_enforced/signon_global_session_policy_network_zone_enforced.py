from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.lib.signon_helpers import (
    active_policies,
    no_active_policies_finding,
    policy_label,
    priority_one_active_rule,
)
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy


class signon_global_session_policy_network_zone_enforced(Check):
    """STIG V-279691 / OKTA-APP-003242.

    Every active Global Session Policy must apply an "IF User's IP is"
    condition mapped to a Network Zone on its Priority 1 active rule so
    access can be allowed or denied per the organization's Access
    Control Policy.

    Unlike the idle / lifetime / persistent-cookie STIGs, V-279691 does
    not exclude the built-in Default Rule, so a zone condition on the
    Default Rule is still effective when no non-default rule sits at
    Priority 1.

    The check emits one finding per active policy because Okta evaluates
    sign-on policies in priority order based on group assignments, and a
    permissive custom policy can govern a user's session even when the
    Default Policy is strict.
    """

    def execute(self) -> list[CheckReportOkta]:
        org_domain = signon_client.provider.identity.org_domain

        policies = active_policies(signon_client.global_session_policies)
        if not policies:
            return [
                no_active_policies_finding(
                    self.metadata(),
                    org_domain,
                    "No active Okta Global Session Policies were returned by the API. "
                    "STIG V-279691 requires the policy that governs each user to map "
                    "User's IP to a Network Zone on its Priority 1 active rule.",
                )
            ]

        findings: list[CheckReportOkta] = []
        for policy in policies:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=policy, org_domain=org_domain
            )
            status, status_extended = _evaluate_policy(policy)
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings


def _evaluate_policy(policy: GlobalSessionPolicy) -> tuple[str, str]:
    label = policy_label(policy)
    rule = priority_one_active_rule(policy)

    if rule is None:
        return (
            "FAIL",
            f"{label} has no Priority 1 active rule. STIG V-279691 requires "
            "the policy to apply an IP-based Network Zone condition on its "
            "Priority 1 active rule.",
        )

    rule_kind = (
        "built-in Default Rule"
        if rule.is_default or rule.name == "Default Rule"
        else "non-default rule"
    )
    has_zones = bool(rule.network_zones_include or rule.network_zones_exclude)

    if has_zones:
        return (
            "PASS",
            f"Priority 1 active {rule_kind} '{rule.name}' in {label} maps "
            "User's IP to a Network Zone.",
        )
    return (
        "FAIL",
        f"Priority 1 active {rule_kind} '{rule.name}' in {label} does not "
        "map User's IP to a Network Zone. The policy cannot allow or deny "
        "access based on the organization's Access Control Policy.",
    )
