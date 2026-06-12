"""Check that every object excluded from a CA policy is covered by another enabled CA policy."""

from collections import Counter

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)

# The Directory Synchronization Accounts role is intentionally excluded from
# broad CA policies and has no fallback policy. Skip it here because
# entra_conditional_access_policy_directory_sync_account_excluded already
# enforces that this exclusion is present.
DIRECTORY_SYNC_ROLE_TEMPLATE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"


def _get_emergency_account_ids(policies):
    """Return the user and group IDs that qualify as emergency access accounts.

    An account is an emergency account if it is excluded from every enabled
    Conditional Access policy that carries a Block grant control — exactly the
    same definition used by entra_emergency_access_exclusion.
    """
    blocking_policies = [
        p
        for p in policies
        if ConditionalAccessGrantControl.BLOCK in p.grant_controls.built_in_controls
    ]
    if not blocking_policies:
        return set(), set()

    total = len(blocking_policies)
    user_counter: Counter = Counter()
    group_counter: Counter = Counter()
    for p in blocking_policies:
        uc = p.conditions.user_conditions
        if not uc:
            continue
        for uid in uc.excluded_users:
            user_counter[uid] += 1
        for gid in uc.excluded_groups:
            group_counter[gid] += 1

    emergency_users = {uid for uid, cnt in user_counter.items() if cnt == total}
    emergency_groups = {gid for gid, cnt in group_counter.items() if cnt == total}
    return emergency_users, emergency_groups


class entra_conditional_access_policy_no_exclusion_gaps(Check):
    """Check that no Conditional Access exclusion creates an uncontrolled gap.

    An exclusion gap exists when a principal (user, group, or role) or
    application is listed in the ``exclude*`` collection of an enabled CA
    policy and does NOT appear in the ``include*`` collection of any other
    enabled CA policy for the same object type.  Such objects sit completely
    outside the CA control plane.

    Intentional exceptions — the Directory Synchronization Accounts role and
    confirmed emergency-access accounts — are skipped automatically.

    - PASS: Every excluded object is covered by at least one other enabled
            policy's include set, or no enabled policy has any exclusions.
    - FAIL: At least one excluded object has no corresponding include entry in
            any other enabled policy.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the exclusion-gap check across all enabled CA policies.

        Returns:
            A list of CheckReportM365 findings, one per enabled policy that
            has exclusions (PASS or FAIL), plus a global PASS when no enabled
            policy uses exclusions at all.
        """
        enabled_policies = [
            p
            for p in entra_client.conditional_access_policies.values()
            if p.state == ConditionalAccessPolicyState.ENABLED
        ]

        if not enabled_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = (
                "No enabled Conditional Access policies found; no exclusion gaps to evaluate."
            )
            return [report]

        emergency_users, emergency_groups = _get_emergency_account_ids(enabled_policies)

        # Build the global include set (union across all enabled policies).
        global_included_users: set = set()
        global_included_groups: set = set()
        global_included_roles: set = set()
        global_included_apps: set = set()

        for policy in enabled_policies:
            uc = policy.conditions.user_conditions
            if uc:
                global_included_users.update(uc.included_users)
                global_included_groups.update(uc.included_groups)
                global_included_roles.update(uc.included_roles)
            ac = policy.conditions.application_conditions
            if ac:
                global_included_apps.update(ac.included_applications)

        findings = []
        any_exclusions_seen = False

        for policy in enabled_policies:
            uc = policy.conditions.user_conditions
            ac = policy.conditions.application_conditions

            excluded_users = set(uc.excluded_users) if uc else set()
            excluded_groups = set(uc.excluded_groups) if uc else set()
            excluded_roles = set(uc.excluded_roles) if uc else set()
            excluded_apps = set(ac.excluded_applications) if ac else set()

            # Drop known intentional exceptions.
            excluded_roles.discard(DIRECTORY_SYNC_ROLE_TEMPLATE_ID)
            excluded_users -= emergency_users
            excluded_groups -= emergency_groups

            if not (excluded_users or excluded_groups or excluded_roles or excluded_apps):
                continue

            any_exclusions_seen = True

            # Identify which excluded objects are NOT covered by the global
            # include set.  "All" in the include set is a sentinel that means
            # every specific ID of that type is already covered by some policy.
            def _uncovered(excluded: set, global_included: set) -> set:
                if "All" in global_included:
                    return set()
                return excluded - global_included

            gap_users = _uncovered(excluded_users, global_included_users)
            gap_groups = _uncovered(excluded_groups, global_included_groups)
            gap_roles = _uncovered(excluded_roles, global_included_roles)
            gap_apps = _uncovered(excluded_apps, global_included_apps)

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if not (gap_users or gap_groups or gap_roles or gap_apps):
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' has no exclusion gaps: "
                    "every excluded object is covered by another enabled policy."
                )
            else:
                parts = []
                if gap_users:
                    parts.append(f"users: {', '.join(sorted(gap_users))}")
                if gap_groups:
                    parts.append(f"groups: {', '.join(sorted(gap_groups))}")
                if gap_roles:
                    parts.append(f"roles: {', '.join(sorted(gap_roles))}")
                if gap_apps:
                    parts.append(f"apps: {', '.join(sorted(gap_apps))}")

                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' excludes objects "
                    f"not covered by any other enabled policy — {'; '.join(parts)}."
                )

            findings.append(report)

        if not any_exclusions_seen:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = (
                "No enabled Conditional Access policy uses any exclusion; no gaps to evaluate."
            )
            return [report]

        return findings
