from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy

DEFAULT_THRESHOLD_MINUTES = 15


class signon_global_session_idle_timeout_15min(Check):
    """STIG V-273186 / OKTA-APP-000020.

    Every active Global Session Policy must have an active Priority 1
    rule that is not the built-in Default Rule, and that rule must set
    the maximum Okta global session idle time to the configured
    threshold or lower (defaults to 15 minutes per STIG; override via
    `okta_max_session_idle_minutes` in the audit config).

    Okta evaluates sign-on policies in priority order based on group
    assignments, so a permissive custom policy can govern a user's
    session even when the Default Policy is strict. The check emits one
    finding per active policy to surface that risk.
    """

    def execute(self) -> list[CheckReportOkta]:
        audit_config = signon_client.audit_config or {}
        threshold = audit_config.get(
            "okta_max_session_idle_minutes", DEFAULT_THRESHOLD_MINUTES
        )
        org_domain = signon_client.provider.identity.org_domain

        active_policies = _active_policies()
        if not active_policies:
            return [_no_policies_finding(self.metadata(), org_domain)]

        findings: list[CheckReportOkta] = []
        for policy in active_policies:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=policy, org_domain=org_domain
            )
            status, status_extended = _evaluate_policy(policy, threshold)
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings


def _evaluate_policy(policy: GlobalSessionPolicy, threshold: int) -> tuple[str, str]:
    label = _policy_label(policy)
    priority_one_rule = _priority_one_active_rule(policy)

    if priority_one_rule is None:
        return (
            "FAIL",
            f"{label} has no Priority 1 active rule. STIG V-273186 requires "
            f"a non-default Priority 1 rule with idle timeout <= {threshold} "
            "minutes.",
        )

    if priority_one_rule.is_default or priority_one_rule.name == "Default Rule":
        return (
            "FAIL",
            f"{label} uses '{priority_one_rule.name}' as its active Priority 1 "
            "rule. The STIG requires a non-default Priority 1 rule.",
        )

    idle_timeout = priority_one_rule.max_session_idle_minutes
    if idle_timeout is None:
        return (
            "FAIL",
            f"Priority 1 non-default rule '{priority_one_rule.name}' in {label} "
            "does not define a maximum Okta global session idle time.",
        )

    if idle_timeout <= threshold:
        return (
            "PASS",
            f"Priority 1 non-default rule '{priority_one_rule.name}' in {label} "
            f"sets the maximum Okta global session idle time to {idle_timeout} "
            f"minutes, meeting the configured threshold of {threshold} minutes.",
        )
    return (
        "FAIL",
        f"Priority 1 non-default rule '{priority_one_rule.name}' in {label} "
        f"sets the maximum Okta global session idle time to {idle_timeout} "
        f"minutes, exceeding the configured threshold of {threshold} minutes.",
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
        "STIG V-273186 requires the policy that governs each user to enforce "
        "a Priority 1 non-default rule with a 15-minute idle timeout."
    )
    return report
