from prowler.lib.check.models import Check, CheckReportOkta
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

        active_policies = _active_policies()
        if not active_policies:
            return [_no_policies_finding(self.metadata(), org_domain)]

        findings: list[CheckReportOkta] = []
        for policy in active_policies:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=policy, org_domain=org_domain
            )
            status, status_extended = _evaluate_policy(policy)
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings


def _evaluate_policy(policy: GlobalSessionPolicy) -> tuple[str, str]:
    label = _policy_label(policy)
    priority_one_rule = _priority_one_active_rule(policy)

    if priority_one_rule is None:
        return (
            "FAIL",
            f"{label} has no Priority 1 active rule. STIG V-279691 requires "
            "the policy to apply an IP-based Network Zone condition on its "
            "Priority 1 active rule.",
        )

    rule_kind = (
        "built-in Default Rule"
        if priority_one_rule.is_default or priority_one_rule.name == "Default Rule"
        else "non-default rule"
    )
    has_zones = bool(
        priority_one_rule.network_zones_include
        or priority_one_rule.network_zones_exclude
    )

    if has_zones:
        return (
            "PASS",
            f"Priority 1 active {rule_kind} '{priority_one_rule.name}' in "
            f"{label} maps User's IP to a Network Zone.",
        )
    return (
        "FAIL",
        f"Priority 1 active {rule_kind} '{priority_one_rule.name}' in {label} "
        "does not map User's IP to a Network Zone. The policy cannot allow "
        "or deny access based on the organization's Access Control Policy.",
    )


def _active_policies() -> list[GlobalSessionPolicy]:
    return sorted(
        [
            policy
            for policy in signon_client.global_session_policies.values()
            if not policy.status or policy.status.upper() == "ACTIVE"
        ],
        key=lambda policy: (
            policy.priority if policy.priority is not None else float("inf"),
            policy.name,
        ),
    )


def _priority_one_active_rule(policy: GlobalSessionPolicy):
    active_rules = sorted(
        [
            rule
            for rule in policy.rules
            if not rule.status or rule.status.upper() == "ACTIVE"
        ],
        key=lambda rule: (
            rule.priority if rule.priority is not None else float("inf"),
            rule.name,
        ),
    )
    if not active_rules:
        return None
    candidate = active_rules[0]
    if candidate.priority != 1:
        return None
    return candidate


def _policy_label(policy: GlobalSessionPolicy) -> str:
    kind = "default" if policy.is_default else "custom"
    priority = policy.priority if policy.priority is not None else "unset"
    return f"Global Session Policy '{policy.name}' (priority {priority}, {kind})"


def _no_policies_finding(metadata, org_domain) -> CheckReportOkta:
    placeholder = GlobalSessionPolicy(
        id="signon-policies-missing",
        name="(no active sign-on policies)",
        priority=1,
        status="MISSING",
        is_default=False,
        rules=[],
    )
    report = CheckReportOkta(
        metadata=metadata, resource=placeholder, org_domain=org_domain
    )
    report.status = "FAIL"
    report.status_extended = (
        "No active Okta Global Session Policies were returned by the API. "
        "STIG V-279691 requires the policy that governs each user to map "
        "User's IP to a Network Zone on its Priority 1 active rule."
    )
    return report
