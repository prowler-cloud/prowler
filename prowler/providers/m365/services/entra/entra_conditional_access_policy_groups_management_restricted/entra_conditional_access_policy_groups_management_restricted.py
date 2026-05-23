from collections import defaultdict

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)

ALL_GROUPS_PROTECTED = (
    "All groups referenced by enabled or report-only Conditional Access Policies "
    "are management-restricted or role-assignable."
)


class entra_conditional_access_policy_groups_management_restricted(Check):
    """Check Conditional Access group scopes are protected against broad management."""

    def execute(self) -> list[CheckReportM365]:
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "PASS"
        report.status_extended = (
            "No enabled or report-only Conditional Access Policy references groups."
        )

        group_usage = defaultdict(lambda: {"include": [], "exclude": []})

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            user_conditions = policy.conditions.user_conditions
            for group_id in user_conditions.included_groups:
                group_usage[group_id]["include"].append(policy)
            for group_id in user_conditions.excluded_groups:
                group_usage[group_id]["exclude"].append(policy)

        if not group_usage:
            findings.append(report)
            return findings

        groups_by_id = {group.id: group for group in entra_client.groups}
        unprotected_groups = []
        unresolved_group_ids = []

        for group_id in sorted(group_usage):
            group = groups_by_id.get(group_id)
            if not group:
                unresolved_group_ids.append(group_id)
                continue

            if not (group.is_management_restricted or group.is_assignable_to_role):
                unprotected_groups.append(group)

        if not unprotected_groups and not unresolved_group_ids:
            report.status_extended = ALL_GROUPS_PROTECTED
            findings.append(report)
            return findings

        report.status = "FAIL"
        report.resource = {
            "unprotected_groups": [group.dict() for group in unprotected_groups],
            "unresolved_group_ids": unresolved_group_ids,
        }
        report.status_extended = self._build_status_extended(
            unprotected_groups,
            unresolved_group_ids,
            group_usage,
        )

        findings.append(report)
        return findings

    @staticmethod
    def _build_status_extended(
        unprotected_groups,
        unresolved_group_ids,
        group_usage,
    ) -> str:
        findings = []
        policy_names = (
            entra_conditional_access_policy_groups_management_restricted._policy_names
        )

        for group in unprotected_groups:
            include_policies = policy_names(group_usage[group.id]["include"])
            exclude_policies = policy_names(group_usage[group.id]["exclude"])
            findings.append(
                f"{group.name} ({group.id}) is not management-restricted or "
                f"role-assignable; include policies: {include_policies}; "
                f"exclude policies: {exclude_policies}"
            )

        for group_id in unresolved_group_ids:
            include_policies = policy_names(group_usage[group_id]["include"])
            exclude_policies = policy_names(group_usage[group_id]["exclude"])
            findings.append(
                f"unresolved group {group_id}; "
                f"include policies: {include_policies}; "
                f"exclude policies: {exclude_policies}"
            )

        return (
            "Conditional Access Policies reference unprotected or unresolved groups: "
            + " | ".join(findings)
            + "."
        )

    @staticmethod
    def _policy_names(policies) -> str:
        if not policies:
            return "none"

        return ", ".join(sorted({policy.display_name for policy in policies}))
