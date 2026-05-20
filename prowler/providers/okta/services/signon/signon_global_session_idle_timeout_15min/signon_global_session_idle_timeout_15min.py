from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.lib.signon_helpers import (
    active_policies,
    no_active_policies_finding,
    policy_label,
    priority_one_active_rule,
)
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

        policies = active_policies(signon_client.global_session_policies)
        if not policies:
            return [
                no_active_policies_finding(
                    self.metadata(),
                    org_domain,
                    "No active Okta Global Session Policies were returned by the API. "
                    "STIG V-273186 requires the policy that governs each user to enforce "
                    "a Priority 1 non-default rule with a 15-minute idle timeout.",
                )
            ]

        findings: list[CheckReportOkta] = []
        for policy in policies:
            report = CheckReportOkta(
                metadata=self.metadata(), resource=policy, org_domain=org_domain
            )
            status, status_extended = _evaluate_policy(policy, threshold)
            report.status = status
            report.status_extended = status_extended
            findings.append(report)
        return findings


def _evaluate_policy(policy: GlobalSessionPolicy, threshold: int) -> tuple[str, str]:
    label = policy_label(policy)
    rule = priority_one_active_rule(policy)

    if rule is None:
        return (
            "FAIL",
            f"{label} has no Priority 1 active rule. STIG V-273186 requires "
            f"a non-default Priority 1 rule with idle timeout <= {threshold} "
            "minutes.",
        )

    if rule.is_default or rule.name == "Default Rule":
        return (
            "FAIL",
            f"{label} uses '{rule.name}' as its active Priority 1 rule. "
            "The STIG requires a non-default Priority 1 rule.",
        )

    idle_timeout = rule.max_session_idle_minutes
    if idle_timeout is None:
        return (
            "FAIL",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            "does not define a maximum Okta global session idle time.",
        )

    if idle_timeout <= threshold:
        return (
            "PASS",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            f"sets the maximum Okta global session idle time to {idle_timeout} "
            f"minutes, meeting the configured threshold of {threshold} minutes.",
        )
    return (
        "FAIL",
        f"Priority 1 non-default rule '{rule.name}' in {label} "
        f"sets the maximum Okta global session idle time to {idle_timeout} "
        f"minutes, exceeding the configured threshold of {threshold} minutes.",
    )
