from collections import Counter

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_emergency_access_users_not_blocked(Check):
    """Ensure that emergency access users are not blocked by any Conditional Access policy.

    This check identifies emergency access (break glass) accounts by finding users
    excluded from all enabled non-blocking Conditional Access policies, then verifies
    that no enabled policy with a block grant control would apply to them.

    - PASS: The emergency access user is not blocked by any Conditional Access policy.
    - FAIL: The emergency access user is blocked by one or more Conditional Access policies.
    - MANUAL: No emergency access users could be identified from the current policies.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for emergency access users not blocked by CA policies.

        Returns:
            list[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        enabled_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state != ConditionalAccessPolicyState.DISABLED
        ]

        if not enabled_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Emergency Access Users",
                resource_id="emergencyAccessUsers",
            )
            report.status = "MANUAL"
            report.status_extended = "No enabled Conditional Access policies found. Emergency access users cannot be identified to verify they are not blocked."
            findings.append(report)
            return findings

        # Separate blocking from non-blocking policies
        non_blocking_policies = [
            policy
            for policy in enabled_policies
            if ConditionalAccessGrantControl.BLOCK
            not in policy.grant_controls.built_in_controls
        ]

        blocking_policies = [
            policy
            for policy in enabled_policies
            if ConditionalAccessGrantControl.BLOCK
            in policy.grant_controls.built_in_controls
        ]

        # Identify emergency access users as those excluded from all non-blocking policies.
        # If there are no non-blocking policies, fall back to all enabled policies.
        identification_policies = (
            non_blocking_policies if non_blocking_policies else enabled_policies
        )
        total_identification_count = len(identification_policies)

        excluded_users_counter = Counter()
        for policy in identification_policies:
            user_conditions = policy.conditions.user_conditions
            if user_conditions:
                for user_id in user_conditions.excluded_users:
                    excluded_users_counter[user_id] += 1

        emergency_access_user_ids = [
            user_id
            for user_id, count in excluded_users_counter.items()
            if count == total_identification_count
        ]

        if not emergency_access_user_ids:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Emergency Access Users",
                resource_id="emergencyAccessUsers",
            )
            report.status = "MANUAL"
            report.status_extended = "No emergency access users identified. No users are excluded from all enabled Conditional Access policies."
            findings.append(report)
            return findings

        for user_id in emergency_access_user_ids:
            user = entra_client.users.get(user_id)
            if not user:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.id,
            )

            policies_blocking_user = []
            for policy in blocking_policies:
                user_conditions = policy.conditions.user_conditions
                if not user_conditions:
                    continue

                is_excluded = user.id in user_conditions.excluded_users

                if is_excluded:
                    continue

                is_included = (
                    "All" in user_conditions.included_users
                    or user.id in user_conditions.included_users
                )

                if is_included:
                    policies_blocking_user.append(policy.display_name)

            if policies_blocking_user:
                report.status = "FAIL"
                policy_names = ", ".join(policies_blocking_user)
                report.status_extended = f"Emergency access user {user.name} is blocked by Conditional Access policies: {policy_names}."
            else:
                report.status = "PASS"
                report.status_extended = f"Emergency access user {user.name} is not blocked by any Conditional Access policy."

            findings.append(report)

        return findings
