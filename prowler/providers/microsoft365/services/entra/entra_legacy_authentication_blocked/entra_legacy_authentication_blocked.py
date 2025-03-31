from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client
from prowler.providers.microsoft365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_legacy_authentication_blocked(Check):
    """Check if at least one Conditional Access policy blocks legacy authentication.

    This check ensures that at least one Conditional Access policy blocks legacy authentication.
    """

    def execute(self) -> list[CheckReportMicrosoft365]:
        """Execute the check to ensure that at least one Conditional Access policy blocks legacy authentication.

        Returns:
            list[CheckReportMicrosoft365]: A list containing the results of the check.
        """
        findings = []
        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy blocks legacy authentication."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if (
                ClientAppType.EXCHANGE_ACTIVE_SYNC
                not in policy.conditions.client_app_types
                or ClientAppType.EXCHANGE_ACTIVE_SYNC
                not in policy.conditions.client_app_types
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportMicrosoft365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports legacy authentication but does not block it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks legacy authentication."
                    break

        findings.append(report)
        return findings
