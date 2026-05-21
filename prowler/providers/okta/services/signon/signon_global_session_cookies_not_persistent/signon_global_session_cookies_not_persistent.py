from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.lib.signon_helpers import (
    active_policies,
    missing_policy_scope_finding,
    no_active_policies_finding,
    policy_label,
    priority_one_active_rule,
)
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy


class signon_global_session_cookies_not_persistent(Check):
    """STIG V-273206 / OKTA-APP-001710.

    Every active Global Session Policy must have an active Priority 1
    rule that is not the built-in Default Rule, and that rule must
    disable persistent global session cookies so the session does not
    survive across browser restarts.

    Okta evaluates sign-on policies in priority order based on group
    assignments, so a permissive custom policy can govern a user's
    session even when the Default Policy is strict. The check emits one
    finding per active policy to surface that risk.
    """

    def execute(self) -> list[CheckReportOkta]:
        org_domain = signon_client.provider.identity.org_domain

        missing_scope = signon_client.missing_scope.get("global_session_policies")
        if missing_scope:
            return [
                missing_policy_scope_finding(self.metadata(), org_domain, missing_scope)
            ]

        policies = active_policies(signon_client.global_session_policies)
        if not policies:
            return [
                no_active_policies_finding(
                    self.metadata(),
                    org_domain,
                    "No active Okta Global Session Policies were returned by the API. "
                    "STIG V-273206 requires the policy that governs each user to enforce "
                    "a Priority 1 non-default rule that disables persistent global "
                    "session cookies.",
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
            f"{label} has no Priority 1 active rule. STIG V-273206 requires "
            "a non-default Priority 1 rule that disables persistent global "
            "session cookies.",
        )

    if rule.is_default or rule.name == "Default Rule":
        return (
            "FAIL",
            f"{label} uses '{rule.name}' as its active Priority 1 rule. "
            "The STIG requires a non-default Priority 1 rule.",
        )

    use_persistent_cookie = rule.use_persistent_cookie
    if use_persistent_cookie is None:
        return (
            "FAIL",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            "does not assert the 'Okta global session cookies persist across "
            "browser sessions' setting.",
        )

    if use_persistent_cookie is False:
        return (
            "PASS",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            "disables persistent global session cookies.",
        )
    return (
        "FAIL",
        f"Priority 1 non-default rule '{rule.name}' in {label} "
        "allows persistent global session cookies, leaving the session active "
        "across browser restarts.",
    )
