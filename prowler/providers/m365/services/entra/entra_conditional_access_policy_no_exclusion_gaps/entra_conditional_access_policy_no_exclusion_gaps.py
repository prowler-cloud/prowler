"""Check that Conditional Access exclusions do not create coverage gaps."""

from collections import Counter, defaultdict

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)

# Directory Synchronization Accounts built-in role template ID. Prowler enforces
# excluding this role (see entra_conditional_access_policy_directory_sync_account_excluded);
# it is intended to have no fallback, so it never counts as a gap here.
DIRECTORY_SYNC_ROLE_TEMPLATE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"


class entra_conditional_access_policy_no_exclusion_gaps(Check):
    """Check that objects excluded from Conditional Access policies remain covered.

    Excluding a principal from a Conditional Access (CA) policy is only safe when
    that principal is still included by *some* enabled CA policy that enforces
    compensating controls. An object excluded everywhere and included nowhere
    sits completely outside CA enforcement, which is how MFA bypass and lateral
    movement against admin accounts happen in real incidents.

    For every enabled CA policy this check walks each exclusion collection and
    verifies the excluded identifier appears in the global include set (the union
    of every include collection across all enabled policies) of its own type.

    - PASS: Every excluded object is included by an enabled policy, or no enabled
            policy uses any exclusion.
    - FAIL: At least one excluded object is never included by any enabled policy.
    """

    # (human label, included attr, excluded attr)
    _USER_COLLECTIONS = [
        ("users", "included_users", "excluded_users"),
        ("groups", "included_groups", "excluded_groups"),
        ("roles", "included_roles", "excluded_roles"),
    ]

    def execute(self) -> list[CheckReportM365]:
        """Execute the Conditional Access exclusion-gap check.

        Returns:
            list[CheckReportM365]: A single-element list with the aggregate result.
        """
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )

        enabled_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state == ConditionalAccessPolicyState.ENABLED
        ]

        if not enabled_policies:
            report.status = "PASS"
            report.status_extended = (
                "No enabled Conditional Access policies found; "
                "no exclusion coverage gaps are possible."
            )
            return [report]

        include_sets = self._build_include_sets(enabled_policies)
        emergency_users, emergency_groups = self._emergency_access_objects()

        # gaps: type label -> {object_id -> set(policy display names that excluded it)}
        gaps = defaultdict(lambda: defaultdict(set))
        any_exclusion = False

        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for label, _, excluded_attr in self._USER_COLLECTIONS:
                    for object_id in getattr(user_conditions, excluded_attr):
                        any_exclusion = True
                        if self._is_expected_user_exclusion(
                            label, object_id, emergency_users, emergency_groups
                        ):
                            continue
                        if object_id not in include_sets[label]:
                            gaps[label][object_id].add(policy.display_name)

            app_conditions = policy.conditions.application_conditions
            if app_conditions:
                for object_id in app_conditions.excluded_applications:
                    any_exclusion = True
                    if object_id not in include_sets["applications"]:
                        gaps["applications"][object_id].add(policy.display_name)

            platform_conditions = policy.conditions.platform_conditions
            if platform_conditions:
                for object_id in platform_conditions.exclude_platforms:
                    any_exclusion = True
                    if object_id not in include_sets["platforms"]:
                        gaps["platforms"][object_id].add(policy.display_name)

        if not any_exclusion:
            report.status = "PASS"
            report.status_extended = (
                "No enabled Conditional Access policy uses exclusions; "
                "no coverage gaps are possible."
            )
            return [report]

        if not gaps:
            report.status = "PASS"
            report.status_extended = (
                "All objects excluded from enabled Conditional Access policies are "
                "covered by an include condition in another enabled policy."
            )
            return [report]

        report.status = "FAIL"
        report.status_extended = (
            "Conditional Access exclusion gaps found "
            f"({self._format_gaps(gaps)}). These objects are excluded but never "
            "included by any enabled policy, leaving them outside CA enforcement."
        )
        return [report]

    def _build_include_sets(self, enabled_policies) -> dict:
        """Union every include collection across enabled policies, keyed by type."""
        include_sets = {
            "users": set(),
            "groups": set(),
            "roles": set(),
            "applications": set(),
            "platforms": set(),
        }
        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for label, included_attr, _ in self._USER_COLLECTIONS:
                    include_sets[label].update(getattr(user_conditions, included_attr))
            app_conditions = policy.conditions.application_conditions
            if app_conditions:
                include_sets["applications"].update(
                    app_conditions.included_applications
                )
            platform_conditions = policy.conditions.platform_conditions
            if platform_conditions:
                include_sets["platforms"].update(platform_conditions.include_platforms)
        return include_sets

    def _emergency_access_objects(self) -> tuple[set, set]:
        """Return user and group IDs that act as emergency access (break-glass).

        Objects excluded from *every* enabled (enforced) Conditional Access policy
        with a Block grant control are intended, compensating gaps and must not be
        reported here. Only ENABLED policies count: report-only policies are not
        enforced, so including them would dilute the "excluded everywhere" check
        and could hide a genuine break-glass account (consistent with execute()).
        """
        blocking_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state == ConditionalAccessPolicyState.ENABLED
            and ConditionalAccessGrantControl.BLOCK
            in policy.grant_controls.built_in_controls
        ]
        if not blocking_policies:
            return set(), set()

        total = len(blocking_policies)
        excluded_users = Counter()
        excluded_groups = Counter()
        for policy in blocking_policies:
            user_conditions = policy.conditions.user_conditions
            if not user_conditions:
                continue
            for user_id in user_conditions.excluded_users:
                excluded_users[user_id] += 1
            for group_id in user_conditions.excluded_groups:
                excluded_groups[group_id] += 1

        emergency_users = {uid for uid, n in excluded_users.items() if n == total}
        emergency_groups = {gid for gid, n in excluded_groups.items() if n == total}
        return emergency_users, emergency_groups

    def _is_expected_user_exclusion(
        self, label, object_id, emergency_users, emergency_groups
    ) -> bool:
        """Exclusions that are intentional by design and must not count as gaps."""
        if label == "roles" and object_id == DIRECTORY_SYNC_ROLE_TEMPLATE_ID:
            return True
        if label == "users" and object_id in emergency_users:
            return True
        if label == "groups" and object_id in emergency_groups:
            return True
        return False

    def _format_gaps(self, gaps) -> str:
        """Render gaps grouped by type with the policies that excluded each object."""
        parts = []
        for label in ("users", "groups", "roles", "applications", "platforms"):
            if label not in gaps:
                continue
            entries = []
            for object_id, policies in gaps[label].items():
                policy_names = ", ".join(sorted(policies))
                entries.append(f"{object_id} (excluded by: {policy_names})")
            parts.append(f"{label}: {'; '.join(entries)}")
        return " | ".join(parts)
