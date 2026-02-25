from collections import Counter

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_emergency_access_exclusion(Check):
    """Check if at least one emergency access account or group is excluded from all Conditional Access policies.

    This check ensures that the tenant has at least one emergency/break glass account
    or account exclusion group that is excluded from all Conditional Access policies.
    This prevents accidental lockout scenarios where misconfigured CA policies could
    block all administrative access to the tenant.

    - PASS: At least one user or group is excluded from all enabled Conditional Access policies,
            or there are no enabled policies.
    - FAIL: No user or group is excluded from all enabled Conditional Access policies.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for emergency access account exclusions.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []

        # Get all enabled CA policies (excluding disabled ones)
        enabled_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state != ConditionalAccessPolicyState.DISABLED
        ]

        # If there are no enabled policies, there's nothing to exclude from
        if not enabled_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = "No enabled Conditional Access policies found. Emergency access exclusions are not required."
            findings.append(report)
            return findings

        total_policy_count = len(enabled_policies)

        # Count how many policies exclude each user
        excluded_users_counter = Counter()
        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for user_id in user_conditions.excluded_users:
                    excluded_users_counter[user_id] += 1

        # Count how many policies exclude each group
        excluded_groups_counter = Counter()
        for policy in enabled_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for group_id in user_conditions.excluded_groups:
                    excluded_groups_counter[group_id] += 1

        # Find users excluded from ALL policies
        users_excluded_from_all = [
            user_id
            for user_id, count in excluded_users_counter.items()
            if count == total_policy_count
        ]

        # Find groups excluded from ALL policies
        groups_excluded_from_all = [
            group_id
            for group_id, count in excluded_groups_counter.items()
            if count == total_policy_count
        ]

        has_emergency_exclusion = bool(
            users_excluded_from_all or groups_excluded_from_all
        )

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )

        if has_emergency_exclusion:
            report.status = "PASS"
            exclusion_details = []
            if users_excluded_from_all:
                exclusion_details.append(f"{len(users_excluded_from_all)} user(s)")
            if groups_excluded_from_all:
                exclusion_details.append(f"{len(groups_excluded_from_all)} group(s)")
            report.status_extended = f"{' and '.join(exclusion_details)} excluded as emergency access across all {total_policy_count} enabled Conditional Access policies."
        else:
            report.status = "FAIL"
            report.status_extended = f"No user or group is excluded as emergency access from all {total_policy_count} enabled Conditional Access policies."

        findings.append(report)

        return findings
