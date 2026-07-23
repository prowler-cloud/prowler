from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
    ConditionalAccessPolicyState,
)

# Applications that must be covered by the Token Protection policy.
EXCHANGE_ONLINE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
SHAREPOINT_ONLINE_APP_ID = "00000003-0000-0ff1-ce00-000000000000"
TEAMS_APP_ID = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"
REQUIRED_APP_IDS = {EXCHANGE_ONLINE_APP_ID, SHAREPOINT_ONLINE_APP_ID, TEAMS_APP_ID}


class entra_conditional_access_policy_token_protection_enforced(Check):
    """Check if a Conditional Access policy enforces Token Protection.

    Token Protection is a Conditional Access session control that reduces token
    replay attacks by requiring device-bound sign-in session tokens. At least one
    enabled Conditional Access policy should enable the ``secureSignInSession``
    session control for the supported applications (Exchange Online, SharePoint
    Online, Teams), target the Windows platform, and apply to mobile apps and desktop
    clients.

    - PASS: An enabled Conditional Access policy enforces Token Protection for the
      supported applications on Windows desktop/mobile clients.
    - FAIL: No Conditional Access policy enforces Token Protection with the required
      scope.
    """

    def _applications_covered(self, included_applications) -> bool:
        if "All" in included_applications:
            return True
        return REQUIRED_APP_IDS.issubset(set(included_applications))

    def _windows_targeted(self, conditions) -> bool:
        platform_conditions = conditions.platform_conditions
        if not platform_conditions:
            return False
        return "windows" in platform_conditions.include_platforms

    def _desktop_clients_targeted(self, conditions) -> bool:
        client_app_types = conditions.client_app_types or []
        return (
            ClientAppType.ALL in client_app_types
            or ClientAppType.MOBILE_APPS_AND_DESKTOP_CLIENTS in client_app_types
        )

    def execute(self) -> list[CheckReportM365]:
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy enforces Token Protection for the supported "
            "applications on Windows desktop and mobile clients."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.user_conditions.included_users:
                continue

            if not policy.session_controls.secure_sign_in_session_enabled:
                continue

            if not self._applications_covered(
                policy.conditions.application_conditions.included_applications
            ):
                continue

            if not self._windows_targeted(policy.conditions):
                continue

            if not self._desktop_clients_targeted(policy.conditions):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enables Token Protection but is in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces Token Protection for the supported applications on Windows desktop and mobile clients."
                break

        findings.append(report)
        return findings
