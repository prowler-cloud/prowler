"""Check if Conditional Access policies reference deleted users, groups, or roles."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_references_deleted_principals(Check):
    """Check that Conditional Access policies do not reference deleted users, groups, or roles.

    Each enabled or report-only Conditional Access policy is inspected. The
    user, group, and role identifiers in the policy conditions are compared
    against the current set of users, groups, and built-in directory roles
    in the tenant. A finding is raised for every policy that contains at
    least one dangling reference.

    - PASS: The policy does not reference any deleted principals.
    - FAIL: The policy references at least one deleted user, group, or role.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []

        existing_user_ids = set(entra_client.users.keys())
        existing_group_ids = {g.id for g in entra_client.groups}

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.user_conditions:
                continue

            user_conditions = policy.conditions.user_conditions
            deleted_references = []

            for uid in user_conditions.included_users:
                if uid not in existing_user_ids and uid not in ("All", "None", "GuestsOrExternalUsers"):
                    deleted_references.append(f"user {uid}")

            for uid in user_conditions.excluded_users:
                if uid not in existing_user_ids and uid not in ("All", "None", "GuestsOrExternalUsers"):
                    deleted_references.append(f"user {uid}")

            for gid in user_conditions.included_groups:
                if gid not in existing_group_ids:
                    deleted_references.append(f"group {gid}")

            for gid in user_conditions.excluded_groups:
                if gid not in existing_group_ids:
                    deleted_references.append(f"group {gid}")

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if not deleted_references:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} does not reference any deleted users, groups, or roles."
            else:
                refs = ", ".join(deleted_references)
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy {policy.display_name} is in report-only mode and references deleted principals: {refs}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy {policy.display_name} references deleted principals: {refs}."

            findings.append(report)

        if not findings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = "No enabled Conditional Access Policies found to evaluate."
            findings.append(report)

        return findings
