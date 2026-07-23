from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    TransferMethod,
)


class entra_conditional_access_policy_authentication_transfer_blocked(Check):
    """Check if at least one Conditional Access policy blocks authentication transfer.

    This check ensures that at least one enabled Conditional Access policy targets
    the authentication transfer flow and blocks access, preventing an authenticated
    session from being seamlessly transferred to another (potentially attacker
    controlled) device.

    - PASS: An enabled Conditional Access policy blocks authentication transfer.
    - FAIL: No Conditional Access policy restricts authentication transfer.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify authentication transfer is blocked by a Conditional Access policy.

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
        report.status_extended = (
            "No Conditional Access Policy blocks authentication transfer."
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

            if not policy.conditions.authentication_flows:
                continue

            if (
                TransferMethod.AUTHENTICATION_TRANSFER
                not in policy.conditions.authentication_flows.transfer_methods
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports authentication transfer but does not block it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks authentication transfer."
                    break

        findings.append(report)
        return findings
