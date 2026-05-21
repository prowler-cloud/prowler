from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# Sentinel identifiers used in conditions.users collections that do not
# correspond to real directory objects and must not be resolved against Graph.
_SENTINEL_IDS = {"All", "None", "GuestsOrExternalUsers"}


class entra_conditional_access_policy_no_deleted_object_references(Check):
    """
    Ensure Conditional Access policies do not reference deleted directory objects.

    Stale references to deleted users, groups, or directory roles silently change
    the runtime behavior of a Conditional Access policy: include* references
    shrink enforcement scope, exclude* references can change exemption logic.
    Either way, the policy stops behaving the way the operator believes it does.

    The directory-object existence check runs once at service init time and is
    cached on the entra client. This check reads from that cache and reports any
    policy whose users/groups/roles inclusion or exclusion collections name an
    identifier that no longer resolves in Microsoft Entra ID.

    - PASS: The policy references no deleted users, groups, or roles.
    - FAIL: The policy references at least one deleted user, group, or role.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []
        unresolved = entra_client.unresolved_directory_object_references

        for policy_id, policy in entra_client.conditional_access_policies.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy_id,
            )

            orphans = self._collect_orphans(policy, unresolved)

            if not orphans:
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access policy {policy.display_name} references no "
                    f"deleted directory objects."
                )
            else:
                report.status = "FAIL"
                report.status_extended = self._format_failure(
                    policy.display_name, orphans
                )

            findings.append(report)

        return findings

    @staticmethod
    def _collect_orphans(policy, unresolved):
        """Walk the six identifier collections on a policy and return orphans.

        Returns:
            list[tuple[str, str, str]]: ``(type, id, side)`` tuples where
                ``type`` is one of ``user|group|role``, ``id`` is the Graph
                identifier that failed to resolve, and ``side`` is one of
                ``include|exclude``.
        """
        if not policy.conditions or not policy.conditions.user_conditions:
            return []

        uc = policy.conditions.user_conditions
        collections = (
            ("user", "include", uc.included_users),
            ("user", "exclude", uc.excluded_users),
            ("group", "include", uc.included_groups),
            ("group", "exclude", uc.excluded_groups),
            ("role", "include", uc.included_roles),
            ("role", "exclude", uc.excluded_roles),
        )

        orphans = []
        for type_, side, identifiers in collections:
            for identifier in identifiers:
                if identifier in _SENTINEL_IDS:
                    continue
                if (type_, identifier) in unresolved:
                    orphans.append((type_, identifier, side))
        return orphans

    @staticmethod
    def _format_failure(display_name, orphans):
        # Group orphans by type for a readable, deterministic message.
        by_type = {"user": [], "group": [], "role": []}
        for type_, identifier, side in orphans:
            by_type[type_].append(f"{identifier} ({side})")

        parts = []
        for type_ in ("user", "group", "role"):
            if by_type[type_]:
                joined = ", ".join(sorted(by_type[type_]))
                parts.append(f"{type_}s: {joined}")

        return (
            f"Conditional Access policy {display_name} references "
            f"{len(orphans)} deleted directory object(s) — {'; '.join(parts)}."
        )
