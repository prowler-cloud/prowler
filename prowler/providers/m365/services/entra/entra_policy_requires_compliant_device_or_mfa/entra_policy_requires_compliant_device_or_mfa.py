from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)

REQUIRED_CLIENT_APP_TYPES = {
    ClientAppType.BROWSER,
    ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS,
}

REQUIRED_GRANT_CONTROLS = {
    ConditionalAccessGrantControl.MFA,
    ConditionalAccessGrantControl.COMPLIANT_DEVICE,
    ConditionalAccessGrantControl.DOMAIN_JOINED_DEVICE,
}


class entra_policy_requires_compliant_device_or_mfa(Check):
    """Check if a Conditional Access policy requires compliant device, hybrid join, or MFA for all users.

    This check verifies that at least one enabled Conditional Access policy
    enforces a compliant device, Microsoft Entra hybrid joined device, or
    multifactor authentication as grant controls with an OR operator, targeting
    all users and all cloud applications with browser and mobile/desktop client
    app types.

    - PASS: An enabled policy requires compliant device, hybrid join, or MFA for all users.
    - FAIL: No policy combines device compliance with MFA as alternative grant controls.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

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
        report.status_extended = "No Conditional Access Policy requires compliant device, hybrid join, or MFA as alternative grant controls for all users."

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

            policy_client_app_types = set(policy.conditions.client_app_types or [])
            if ClientAppType.ALL not in policy_client_app_types and not REQUIRED_CLIENT_APP_TYPES.issubset(policy_client_app_types):
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports the requirement of compliant device, hybrid join, or MFA for all users but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires compliant device, hybrid join, or MFA for all users."
                break

        findings.append(report)

        return findings
