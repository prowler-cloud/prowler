from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    TransferMethod,
)


class entra_conditional_access_policy_device_code_flow_blocked(Check):
    """Check if at least one Conditional Access policy blocks device code flow.

    This check ensures that at least one enabled Conditional Access policy
    targets the device code authentication flow and blocks access, protecting
    against phishing attacks that abuse this flow (e.g., Storm-2372).

    - PASS: An enabled Conditional Access policy blocks device code flow.
    - FAIL: No Conditional Access policy restricts device code flow.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify device code flow is blocked by a Conditional Access policy.

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
        report.status_extended = "No Conditional Access Policy blocks device code flow."

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
                TransferMethod.DEVICE_CODE_FLOW
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
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports device code flow but does not block it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks device code flow."
                    break

        findings.append(report)
        return findings
