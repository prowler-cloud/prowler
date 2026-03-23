from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)
from prowler.providers.m365.services.intune.intune_client import intune_client
from prowler.providers.m365.services.intune.intune_service import Intune


class entra_conditional_access_policy_mdm_compliant_device_required(Check):
    """Ensure a Conditional Access policy requires an MDM-compliant device for all cloud app access.

    This check verifies that at least one enabled Conditional Access policy enforces
    the compliant device grant control for all cloud applications and that Microsoft
    Intune compliance prerequisites are configured to make that MDM requirement
    effective.

    - PASS: An enabled policy requires a compliant device for all cloud app access.
    - FAIL: No policy mandates device compliance, or Intune prerequisites are not configured.
    - MANUAL: Intune prerequisites cannot be verified due to missing visibility.
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
        report.status_extended = "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."

        reporting_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if not self._is_candidate_policy(policy):
                continue

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                if reporting_policy is None:
                    reporting_policy = policy
                continue

            report = self._build_policy_report(policy)

            verification_error = getattr(intune_client, "verification_error", None)
            if verification_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, but Microsoft "
                    f"Intune MDM compliance prerequisites could not be verified. {verification_error}"
                )
                findings.append(report)
                return findings

            compliance_policies = (
                getattr(intune_client, "compliance_policies", []) or []
            )
            if not compliance_policies:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, but no Microsoft "
                    "Intune device compliance policies are configured."
                )
                findings.append(report)
                return findings

            assigned_policies = [
                compliance_policy
                for compliance_policy in compliance_policies
                if getattr(compliance_policy, "assignment_count", 0) > 0
            ]
            if not assigned_policies:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, but no Microsoft "
                    "Intune device compliance policy is assigned."
                )
                findings.append(report)
                return findings

            settings = getattr(intune_client, "settings", None)
            secure_by_default = getattr(settings, "secure_by_default", None)
            if secure_by_default is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, but Microsoft "
                    "Intune allows devices without an assigned compliance policy to "
                    "remain compliant."
                )
                findings.append(report)
                return findings

            managed_devices = getattr(intune_client, "managed_devices", []) or []
            mdm_compliant_devices = [
                managed_device
                for managed_device in managed_devices
                if getattr(managed_device, "compliance_state", "") == "compliant"
                and Intune.is_mdm_managed_device(
                    getattr(managed_device, "management_agent", "")
                )
            ]
            if not mdm_compliant_devices:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, but Microsoft "
                    "Intune does not currently report any compliant MDM-managed devices."
                )
                findings.append(report)
                return findings

            report.status = "PASS"
            if secure_by_default is None:
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, and Microsoft Intune "
                    "is configured with assigned compliance policies and at least one "
                    "compliant MDM-managed device. Microsoft Graph did not return "
                    "device management settings, so secure-by-default compliance "
                    "evaluation could not be verified."
                )
            else:
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires an "
                    "MDM-compliant device for all cloud app access, and Microsoft Intune "
                    "is configured with assigned compliance policies, secure-by-default "
                    "compliance evaluation, and at least one compliant MDM-managed device."
                )
            findings.append(report)
            return findings

        if reporting_policy is not None:
            report = self._build_policy_report(reporting_policy)
            report.status = "FAIL"
            report.status_extended = (
                f"Conditional Access Policy '{reporting_policy.display_name}' reports "
                "the requirement of an MDM-compliant device for all cloud app access "
                "but does not enforce it."
            )

        findings.append(report)
        return findings

    def _build_policy_report(self, policy: ConditionalAccessPolicy) -> CheckReportM365:
        return CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name=policy.display_name,
            resource_id=policy.id,
        )

    @staticmethod
    def _is_candidate_policy(policy: ConditionalAccessPolicy) -> bool:
        if policy.state == ConditionalAccessPolicyState.DISABLED:
            return False

        application_conditions = policy.conditions.application_conditions
        user_conditions = policy.conditions.user_conditions
        if not application_conditions or not user_conditions:
            return False

        if "All" not in user_conditions.included_users:
            return False

        if "All" not in application_conditions.included_applications:
            return False

        if application_conditions.excluded_applications != []:
            return False

        if (
            ConditionalAccessGrantControl.COMPLIANT_DEVICE
            not in policy.grant_controls.built_in_controls
        ):
            return False

        if policy.grant_controls.operator == GrantControlOperator.OR and (
            len(policy.grant_controls.built_in_controls) > 1
            or policy.grant_controls.authentication_strength is not None
        ):
            return False

        return True
