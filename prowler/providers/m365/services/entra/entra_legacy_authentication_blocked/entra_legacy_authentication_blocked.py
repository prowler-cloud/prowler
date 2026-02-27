from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_legacy_authentication_blocked(Check):
    """Check if a Conditional Access policy blocks legacy authentication for all users and cloud apps.

    This check verifies that an enabled Conditional Access policy exists that blocks
    legacy authentication protocols (Exchange ActiveSync and other legacy clients)
    targeting all users and all cloud applications.
    - PASS: An enabled policy blocks legacy authentication for all users and cloud apps.
    - FAIL: No enabled policy blocks legacy authentication, or the policy is in report-only mode.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the legacy authentication blocking check.

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
                or ClientAppType.OTHER_CLIENTS
                not in policy.conditions.client_app_types
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
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports legacy authentication but does not block it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks legacy authentication."
                    break

        findings.append(report)
        return findings
