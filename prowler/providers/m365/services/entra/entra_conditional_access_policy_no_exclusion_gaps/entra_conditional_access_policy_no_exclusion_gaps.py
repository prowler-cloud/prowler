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
    that principal is still covered by *some* enabled CA policy that enforces
    compensating controls. An object excluded everywhere and included nowhere
    sits completely outside CA enforcement, which is how MFA bypass and lateral
    movement against admin accounts happen in real incidents.

    For every enabled CA policy this check walks each exclusion collection and
    verifies the excluded object is still in scope of another enabled policy: one
    that includes it (explicitly, or via the "All" wildcard) and does not itself
    exclude it. A wildcard belonging to the policy that excludes the object does
    not count, so a one-off exclusion with no compensating policy is reported as
    a gap.

    Only principals and target apps are evaluated (users, groups, roles,
    applications). Platform and location exclusions are scoping conditions rather
    than principals removed from enforcement, so they are out of scope.

    - PASS: Every excluded object stays in scope of another enabled policy, or no
            enabled policy uses any exclusion.
    - FAIL: At least one excluded object is in scope of no other enabled policy.
    """

    # (label, conditions attribute, included attr, excluded attr, wildcard token).
    # The wildcard token, when present in an include collection, scopes a policy
    # to every object of that type. Groups and roles have no wildcard: they are
    # always explicit identifiers and transitive group/role expansion is out of
    # scope for v1, so an excluded group/role is only "covered" when the same
    # identifier is explicitly included by another enabled policy.
    _COLLECTIONS = [
        ("users", "user_conditions", "included_users", "excluded_users", "All"),
        ("groups", "user_conditions", "included_groups", "excluded_groups", None),
        ("roles", "user_conditions", "included_roles", "excluded_roles", None),
        (
            "applications",
            "application_conditions",
            "included_applications",
            "excluded_applications",
            "All",
        ),
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

        emergency_users, emergency_groups = self._emergency_access_objects()

        # gaps: type label -> set of excluded object IDs with no compensating policy
        gaps = defaultdict(set)
        any_exclusion = False

        for policy in enabled_policies:
            for (
                label,
                conditions_attr,
                included_attr,
                excluded_attr,
                wildcard,
            ) in self._COLLECTIONS:
                conditions = getattr(policy.conditions, conditions_attr)
                if not conditions:
                    continue
                for object_id in getattr(conditions, excluded_attr):
                    any_exclusion = True
                    if self._is_expected_exclusion(
                        label, object_id, emergency_users, emergency_groups
                    ):
                        continue
                    if not self._is_covered(
                        object_id,
                        conditions_attr,
                        included_attr,
                        excluded_attr,
                        wildcard,
                        enabled_policies,
                    ):
                        gaps[label].add(object_id)

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
                "Every object excluded from an enabled Conditional Access policy is "
                "still in scope of another enabled policy, so a compensating control "
                "remains in effect."
            )
            return [report]

        report.status = "FAIL"
        report.status_extended = (
            "Conditional Access exclusion gaps found "
            f"({self._format_gaps(gaps, self._build_name_index())}). These objects "
            "are excluded but in scope of no other enabled policy, leaving them "
            "outside CA enforcement."
        )
        return [report]

    def _build_name_index(self) -> dict:
        """Map excluded object IDs to display names per type, for readable findings.

        Users, groups, and applications resolve to their display name; roles have
        no loaded name catalog, so role template IDs are shown as-is. Unresolved
        IDs (for example deleted principals still referenced by a policy) fall
        back to the raw identifier.
        """
        users = {
            uid: user.name
            for uid, user in (getattr(entra_client, "users", {}) or {}).items()
            if getattr(user, "name", None)
        }
        groups = {
            group.id: group.name
            for group in (getattr(entra_client, "groups", []) or [])
            if getattr(group, "name", None)
        }
        applications = {
            sp.app_id: sp.name
            for sp in (getattr(entra_client, "service_principals", {}) or {}).values()
            if getattr(sp, "app_id", None) and getattr(sp, "name", None)
        }
        return {"users": users, "groups": groups, "applications": applications}

    def _is_covered(
        self,
        object_id,
        conditions_attr,
        included_attr,
        excluded_attr,
        wildcard,
        enabled_policies,
    ) -> bool:
        """Return True if any enabled policy keeps ``object_id`` in scope.

        A policy keeps the object in scope when it includes it —explicitly or via
        the type's wildcard token— and does not also exclude it. The wildcard of a
        policy that itself excludes the object does not count, which is what makes
        a one-off exclusion with no compensating policy a real gap.
        """
        for policy in enabled_policies:
            conditions = getattr(policy.conditions, conditions_attr)
            if not conditions:
                continue
            if object_id in getattr(conditions, excluded_attr):
                continue
            included = getattr(conditions, included_attr)
            if object_id in included or (wildcard is not None and wildcard in included):
                return True
        return False

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

    def _is_expected_exclusion(
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

    def _format_gaps(self, gaps, name_index) -> str:
        """Render the orphaned objects grouped by type, by display name when known.

        Each ID is shown as its display name when resolvable; unresolved IDs (and
        all roles, which have no name catalog) fall back to the raw identifier.
        """
        parts = []
        for label in ("users", "groups", "roles", "applications"):
            if label not in gaps:
                continue
            names = name_index.get(label, {})
            rendered = sorted(
                names.get(object_id, object_id) for object_id in gaps[label]
            )
            parts.append(f"{label}: {', '.join(rendered)}")
        return " | ".join(parts)
