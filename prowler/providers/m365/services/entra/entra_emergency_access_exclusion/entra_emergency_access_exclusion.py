from collections import Counter

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_emergency_access_exclusion(Check):
    """Check that at least one emergency access account or group is excluded
    from every enabled Conditional Access policy with a `Block` grant control.

    Emergency access (break glass) accounts are, by definition, accounts that
    cannot be blocked by Conditional Access. Membership of an account in the
    exclusion list of every enabled blocking policy is therefore the necessary
    condition for it to act as a true emergency account: if any enabled
    blocking policy applies to it, a misconfiguration of that policy can lock
    out the tenant.

    - PASS: At least one user or group is excluded from every enabled
            Conditional Access policy with a `Block` grant control, or no
            enabled blocking Conditional Access policy exists.
    - FAIL: One or more enabled blocking Conditional Access policies exist and
            no user or group is excluded from all of them.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for emergency access account exclusions from
        blocking Conditional Access policies.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )

        blocking_policies = [
            policy
            for policy in entra_client.conditional_access_policies.values()
            if policy.state != ConditionalAccessPolicyState.DISABLED
            and ConditionalAccessGrantControl.BLOCK
            in policy.grant_controls.built_in_controls
        ]

        if not blocking_policies:
            report.status = "PASS"
            report.status_extended = "No enabled Conditional Access policies with a Block grant control found. Emergency access exclusions are not required."
            findings.append(report)
            return findings

        total_blocking_count = len(blocking_policies)

        excluded_users_counter = Counter()
        excluded_groups_counter = Counter()
        for policy in blocking_policies:
            user_conditions = policy.conditions.user_conditions
            if not user_conditions:
                continue
            for user_id in user_conditions.excluded_users:
                excluded_users_counter[user_id] += 1
            for group_id in user_conditions.excluded_groups:
                excluded_groups_counter[group_id] += 1

        emergency_user_ids = [
            user_id
            for user_id, count in excluded_users_counter.items()
            if count == total_blocking_count
        ]
        emergency_group_ids = [
            group_id
            for group_id, count in excluded_groups_counter.items()
            if count == total_blocking_count
        ]

        if not (emergency_user_ids or emergency_group_ids):
            report.status = "FAIL"
            report.status_extended = f"No user or group is excluded as emergency access from all {total_blocking_count} enabled Conditional Access policies with a Block grant control."
            findings.append(report)
            return findings

        exclusion_details = []
        if emergency_user_ids:
            user_names = []
            for uid in emergency_user_ids:
                user = entra_client.users.get(uid)
                user_names.append(user.name if user else uid)
            exclusion_details.append(f"user(s): {', '.join(user_names)}")
        if emergency_group_ids:
            groups_by_id = {g.id: g for g in entra_client.groups}
            group_names = []
            for gid in emergency_group_ids:
                group = groups_by_id.get(gid)
                group_names.append(group.name if group else gid)
            exclusion_details.append(f"group(s): {', '.join(group_names)}")

        report.status = "PASS"
        report.status_extended = f"Emergency access {' and '.join(exclusion_details)} excluded from all {total_blocking_count} enabled Conditional Access policies with a Block grant control."
        findings.append(report)

        return findings
