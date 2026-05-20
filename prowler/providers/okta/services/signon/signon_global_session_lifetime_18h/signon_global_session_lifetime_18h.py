from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.signon.lib.signon_helpers import (
    active_policies,
    no_active_policies_finding,
    policy_label,
    priority_one_active_rule,
)
from prowler.providers.okta.services.signon.signon_client import signon_client
from prowler.providers.okta.services.signon.signon_service import GlobalSessionPolicy

DEFAULT_THRESHOLD_MINUTES = 18 * 60


class signon_global_session_lifetime_18h(Check):
    """STIG V-273203 / OKTA-APP-001665.

    Every active Global Session Policy must have an active Priority 1
    rule that is not the built-in Default Rule, and that rule must set
    the maximum Okta global session lifetime to the configured threshold
    or lower (defaults to 18 hours per STIG; override via
    `okta_max_session_lifetime_minutes` in the audit config).

    Okta evaluates sign-on policies in priority order based on group
    assignments, so a permissive custom policy can govern a user's
    session even when the Default Policy is strict. The check emits one
    finding per active policy to surface that risk.
    """

    def execute(self) -> list[CheckReportOkta]:
        audit_config = signon_client.audit_config or {}
        threshold = audit_config.get(
            "okta_max_session_lifetime_minutes", DEFAULT_THRESHOLD_MINUTES
        )
        org_domain = signon_client.provider.identity.org_domain

        policies = active_policies(signon_client.global_session_policies)
        if not policies:
            return [
                no_active_policies_finding(
                    self.metadata(),
                    org_domain,
                    "No active Okta Global Session Policies were returned by the API. "
                    "STIG V-273203 requires the policy that governs each user to enforce "
                    "a Priority 1 non-default rule with an 18-hour session lifetime.",
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
            f"{label} has no Priority 1 active rule. STIG V-273203 requires "
            f"a non-default Priority 1 rule with session lifetime <= {threshold} "
            "minutes.",
        )

    if rule.is_default or rule.name == "Default Rule":
        return (
            "FAIL",
            f"{label} uses '{rule.name}' as its active Priority 1 rule. "
            "The STIG requires a non-default Priority 1 rule.",
        )

    lifetime = rule.max_session_lifetime_minutes
    if lifetime is None:
        return (
            "FAIL",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            "does not define a maximum Okta global session lifetime.",
        )

    if lifetime == 0:
        return (
            "FAIL",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            "disables the maximum Okta global session lifetime by setting it "
            "to 0 minutes.",
        )

    if lifetime <= threshold:
        return (
            "PASS",
            f"Priority 1 non-default rule '{rule.name}' in {label} "
            f"sets the maximum Okta global session lifetime to {lifetime} "
            f"minutes, meeting the configured threshold of {threshold} minutes.",
        )
    return (
        "FAIL",
        f"Priority 1 non-default rule '{rule.name}' in {label} "
        f"sets the maximum Okta global session lifetime to {lifetime} minutes, "
        f"exceeding the configured threshold of {threshold} minutes.",
    )
