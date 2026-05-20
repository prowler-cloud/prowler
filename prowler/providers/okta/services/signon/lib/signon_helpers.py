"""Shared helpers for the OKTA sign-on STIG checks.

The four `signon_global_session_*` checks share the same plumbing:
they iterate active Global Session Policies in priority order, locate
each policy's Priority 1 active rule, and emit one finding per policy.
This module centralises that plumbing so each check can stay focused
on its STIG-specific predicate.
"""

from typing import Optional

from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
)


def active_policies(
    global_session_policies: dict[str, GlobalSessionPolicy],
) -> list[GlobalSessionPolicy]:
    """Return active policies sorted by priority (ascending, name as tiebreaker).

    A policy with no `status` is treated as ACTIVE because the Okta SDK
    sometimes omits the field on default policies.
    """
    return sorted(
        [
            policy
            for policy in global_session_policies.values()
            if not policy.status or policy.status.upper() == "ACTIVE"
        ],
        key=lambda policy: (
            policy.priority if policy.priority is not None else float("inf"),
            policy.name,
        ),
    )


def priority_one_active_rule(
    policy: GlobalSessionPolicy,
) -> Optional[GlobalSessionPolicyRule]:
    """Return the policy's Priority 1 active rule, or None.

    Okta's evaluator skips inactive rules, so we first filter to active
    rules and pick the highest-priority one. If that rule is not at
    priority 1 we return None — the policy effectively has no
    priority-1 rule for evaluation purposes.
    """
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


def policy_label(policy: GlobalSessionPolicy) -> str:
    kind = "default" if policy.is_default else "custom"
    priority = policy.priority if policy.priority is not None else "unset"
    return f"Global Session Policy '{policy.name}' (priority {priority}, {kind})"


def no_active_policies_finding(
    metadata, org_domain: str, status_extended: str
) -> CheckReportOkta:
    """Build the FAIL finding emitted when no active sign-on policies exist."""
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
    report.status_extended = status_extended
    return report
