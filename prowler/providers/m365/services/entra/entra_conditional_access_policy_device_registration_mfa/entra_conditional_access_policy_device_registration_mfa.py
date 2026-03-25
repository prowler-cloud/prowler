from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
    UserAction,
)

# Microsoft Intune Enrollment application ID
INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"

# Microsoft Intune application ID
MICROSOFT_INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000"


class entra_conditional_access_policy_device_registration_mfa(Check):
    """Ensure MFA is required for device registration and Intune enrollment.

    This check evaluates whether Conditional Access policies require multifactor
    authentication for device registration and Intune enrollment to prevent
    unauthorized device enrollment.

    - PASS: Enabled CA policies require MFA for both device registration and
      Intune enrollment with sign-in frequency set to Every Time.
    - FAIL: Device registration or Intune enrollment does not require MFA
      through enforced Conditional Access policies.
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
        report.status_extended = "No Conditional Access Policy requires MFA for device registration or Intune enrollment."

        device_reg_enforced = False
        device_reg_policy = None
        device_reg_reporting_policy = None

        intune_enforced = False
        intune_policy = None
        intune_reporting_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            # Check device registration MFA
            if (
                not device_reg_enforced
                and UserAction.REGISTER_DEVICE
                in policy.conditions.application_conditions.included_user_actions
                and ConditionalAccessGrantControl.MFA
                in policy.grant_controls.built_in_controls
            ):
                if policy.state == ConditionalAccessPolicyState.ENABLED:
                    device_reg_enforced = True
                    device_reg_policy = policy
                elif (
                    policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                    and device_reg_reporting_policy is None
                ):
                    device_reg_reporting_policy = policy

            # Check Intune enrollment MFA with sign-in frequency every time
            included_apps = (
                policy.conditions.application_conditions.included_applications
            )
            excluded_apps = (
                policy.conditions.application_conditions.excluded_applications
            )
            targets_intune = (
                INTUNE_ENROLLMENT_APP_ID in included_apps
                or MICROSOFT_INTUNE_APP_ID in included_apps
                or "All" in included_apps
            )
            intune_excluded = (
                INTUNE_ENROLLMENT_APP_ID in excluded_apps
                or MICROSOFT_INTUNE_APP_ID in excluded_apps
            )

            if (
                not intune_enforced
                and targets_intune
                and not intune_excluded
                and ConditionalAccessGrantControl.MFA
                in policy.grant_controls.built_in_controls
                and policy.session_controls.sign_in_frequency.is_enabled
                and policy.session_controls.sign_in_frequency.interval
                == SignInFrequencyInterval.EVERY_TIME
            ):
                if policy.state == ConditionalAccessPolicyState.ENABLED:
                    intune_enforced = True
                    intune_policy = policy
                elif (
                    policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                    and intune_reporting_policy is None
                ):
                    intune_reporting_policy = policy

        if device_reg_enforced and intune_enforced:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=device_reg_policy,
                resource_name=device_reg_policy.display_name,
                resource_id=device_reg_policy.id,
            )
            report.status = "PASS"
            report.status_extended = (
                f"Conditional Access Policy '{device_reg_policy.display_name}' "
                f"enforces MFA for device registration and policy "
                f"'{intune_policy.display_name}' enforces MFA with Every Time "
                f"sign-in frequency for Intune enrollment."
            )
        else:
            issues = []
            if not device_reg_enforced:
                if device_reg_reporting_policy:
                    issues.append(
                        f"policy '{device_reg_reporting_policy.display_name}' "
                        f"reports MFA for device registration but does not enforce it"
                    )
                else:
                    issues.append("no policy requires MFA for device registration")
            if not intune_enforced:
                if intune_reporting_policy:
                    issues.append(
                        f"policy '{intune_reporting_policy.display_name}' "
                        f"reports MFA for Intune enrollment but does not enforce it"
                    )
                else:
                    issues.append(
                        "no policy requires MFA with Every Time sign-in "
                        "frequency for Intune enrollment"
                    )
            report.status_extended = (
                "Conditional Access Policy gap: " + "; ".join(issues) + "."
            )

        findings.append(report)
        return findings
