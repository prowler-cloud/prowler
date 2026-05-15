"""Check if a Conditional Access policy explicitly targets Azure DevOps."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)

AZURE_DEVOPS_APP_ID = "499b84ac-1321-427f-aa17-267ca6975798"


class entra_conditional_access_policy_explicitly_targets_azure_devops(Check):
    """Check that an enabled Conditional Access policy explicitly targets Azure DevOps."""

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for explicit Azure DevOps targeting.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No enabled Conditional Access Policy explicitly targets Azure DevOps."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state != ConditionalAccessPolicyState.ENABLED:
                continue

            if not policy.conditions.application_conditions:
                continue

            if (
                AZURE_DEVOPS_APP_ID
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            report.status = "PASS"
            report.status_extended = f"Conditional Access Policy {policy.display_name} explicitly targets Azure DevOps."
            break

        findings.append(report)
        return findings
