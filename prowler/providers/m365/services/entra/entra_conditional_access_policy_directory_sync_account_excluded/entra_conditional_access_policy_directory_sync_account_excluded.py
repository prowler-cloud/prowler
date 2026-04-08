"""Check if Conditional Access policies exclude the Directory Synchronization Account."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)

# The Directory Synchronization Accounts built-in role template ID in Entra ID.
# This role is assigned to the Microsoft Entra Connect Sync service account and
# does not support multifactor authentication.
DIRECTORY_SYNC_ROLE_TEMPLATE_ID = "d29b2b05-8046-44ba-8758-1e26182fcf32"


class entra_conditional_access_policy_directory_sync_account_excluded(Check):
    """Check that Conditional Access policies exclude the Directory Synchronization Account.

    The Microsoft Entra Connect Sync Account cannot support MFA. Conditional
    Access policies scoped to all users and all cloud apps must explicitly
    exclude the Directory Synchronization Accounts role to prevent breaking
    directory synchronization.

    - PASS: The policy excludes the Directory Synchronization Accounts role.
    - FAIL: The policy does not exclude the Directory Synchronization Accounts role.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for Directory Sync Account exclusion from Conditional Access policies.

        Iterates through all enabled Conditional Access policies that target
        all users and all cloud applications, verifying each one excludes the
        Directory Synchronization Accounts role.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.user_conditions:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if not policy.conditions.application_conditions:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if (
                DIRECTORY_SYNC_ROLE_TEMPLATE_ID
                in policy.conditions.user_conditions.excluded_roles
            ):
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' excludes the Directory Synchronization Accounts role."
            else:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' does not exclude the Directory Synchronization Accounts role, which may break Entra Connect sync."

            findings.append(report)

        if not findings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = "No Conditional Access Policy targets all users and all cloud apps, so no Directory Synchronization Accounts exclusion is needed."
            findings.append(report)

        return findings
