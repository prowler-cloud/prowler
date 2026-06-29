from collections import defaultdict

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_groups_management_restricted(Check):
    """Ensure Conditional Access group scopes are protected against broad management.

    Security groups referenced by enabled or report-only Conditional Access
    policies (in ``includeGroups`` or ``excludeGroups``) are privileged control
    points: anyone able to change their membership can silently bypass or weaken
    a policy. This check reports one finding per referenced group.

    - PASS: The group is management-restricted or role-assignable, or no enabled
      or report-only policy references any group.
    - FAIL: The group is neither management-restricted nor role-assignable.
    - MANUAL: The group reference no longer resolves in Microsoft Entra ID and
      must be verified or removed.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports, one per group referenced by an enabled or
            report-only Conditional Access policy.
        """
        findings = []

        group_usage = defaultdict(lambda: {"include": [], "exclude": []})

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            user_conditions = policy.conditions.user_conditions
            if not user_conditions:
                continue

            for group_id in user_conditions.included_groups:
                group_usage[group_id]["include"].append(policy)
            for group_id in user_conditions.excluded_groups:
                group_usage[group_id]["exclude"].append(policy)

        if not group_usage:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = (
                "No enabled or report-only Conditional Access Policy references "
                "groups."
            )
            findings.append(report)
            return findings

        groups_by_id = {group.id: group for group in entra_client.groups}

        for group_id in sorted(group_usage):
            usage = self._policy_usage(group_usage[group_id])
            group = groups_by_id.get(group_id)

            if not group:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name=group_id,
                    resource_id=group_id,
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Group {group_id} referenced by Conditional Access Policies "
                    f"could not be resolved in Microsoft Entra ID; verify the group "
                    f"exists or remove the stale reference ({usage})."
                )
                findings.append(report)
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=group,
                resource_name=group.name,
                resource_id=group.id,
            )

            if group.is_management_restricted or group.is_assignable_to_role:
                report.status = "PASS"
                report.status_extended = (
                    f"Group {group.name} ({group.id}) referenced by Conditional "
                    f"Access Policies is management-restricted or role-assignable."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Group {group.name} ({group.id}) referenced by Conditional "
                    f"Access Policies is neither management-restricted nor "
                    f"role-assignable ({usage})."
                )

            findings.append(report)

        return findings

    @staticmethod
    def _policy_usage(usage) -> str:
        """Render the include/exclude policy usage of a group as a string.

        Args:
            usage: Mapping with ``include`` and ``exclude`` lists of policies.

        Returns:
            A string such as ``"include policies: A; exclude policies: B"``.
        """

        def policy_names(policies):
            if not policies:
                return "none"
            return ", ".join(sorted({policy.display_name for policy in policies}))

        return (
            f"include policies: {policy_names(usage['include'])}; "
            f"exclude policies: {policy_names(usage['exclude'])}"
        )
