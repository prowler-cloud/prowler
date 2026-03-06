from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    AdminRoles,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)

REQUIRED_GRANT_CONTROLS = {
    ConditionalAccessGrantControl.MFA,
    ConditionalAccessGrantControl.COMPLIANT_DEVICE,
    ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
}
ADMIN_ROLE_IDS = {role.value for role in AdminRoles}


class entra_conditional_access_policy_compliant_device_hybrid_joined_device_mfa_required(
    Check
):
    """Check that CA enforces compliant or hybrid joined device or MFA for admins/all users."""

    def _targets_admins_or_all_users(self, policy) -> bool:
        if "All" in policy.conditions.user_conditions.included_users:
            return True

        included_roles = set(policy.conditions.user_conditions.included_roles)
        return bool(ADMIN_ROLE_IDS.intersection(included_roles))

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy requires compliant device, hybrid joined device, or MFA for admin roles or all users across all cloud apps."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not self._targets_admins_or_all_users(policy):
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            policy_grant_controls = set(policy.grant_controls.built_in_controls)
            if not REQUIRED_GRANT_CONTROLS.issubset(policy_grant_controls):
                continue

            if policy.grant_controls.operator != GrantControlOperator.OR:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy {policy.display_name} reports compliant device, hybrid joined device, or MFA for admin roles or all users but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} enforces compliant device, hybrid joined device, or MFA for admin roles or all users across all cloud apps."
                break

        findings.append(report)
        return findings
