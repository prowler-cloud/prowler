from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
)


class entra_conditional_access_policy_target_resources_configured(Check):
    """Ensure every Conditional Access policy targets at least one resource.

    A Conditional Access policy without any target resources (cloud apps,
    user actions, authentication context class references or an application
    filter) is silently accepted by Microsoft Entra but enforces nothing.
    This creates a false sense of security because the policy appears active
    yet never triggers.

    - PASS: The policy targets at least one resource.
    - FAIL: The policy has no target resources and therefore enforces nothing.
    - MANUAL: Conditional Access policies could not be (fully) read.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # If there was an error reading policies, emit per-policy findings
        # for whatever was read plus a tenant-level MANUAL finding.
        if entra_client.conditional_access_policies_error:
            findings.extend(self._evaluate_policies())
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Conditional Access policies could not be fully retrieved: "
                f"{entra_client.conditional_access_policies_error}. "
                "Some policies may be missing from the evaluation. "
                "Verify that the Policy.Read.All permission is granted "
                "and the tenant has a Microsoft Entra ID P1 licence."
            )
            findings.append(report)
            return findings

        # No error and no policies -> nothing to evaluate.
        if not entra_client.conditional_access_policies:
            return findings

        findings.extend(self._evaluate_policies())
        return findings

    def _evaluate_policies(self) -> list[CheckReportM365]:
        """Evaluate each Conditional Access policy for target resource configuration.

        Returns:
            A list of per-policy findings.
        """
        findings = []

        for policy in entra_client.conditional_access_policies.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            state_label = policy.state.value
            app_conditions = policy.conditions.application_conditions

            if not app_conditions:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy {policy.display_name} "
                    f"({state_label}) has no target resources (cloud apps, "
                    "user actions, authentication context or app filter) "
                    "and therefore enforces nothing."
                )
                findings.append(report)
                continue

            is_targeted = self._is_policy_targeted(app_conditions)

            if is_targeted:
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy {policy.display_name} "
                    f"({state_label}) targets at least one resource."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy {policy.display_name} "
                    f"({state_label}) has no target resources (cloud apps, "
                    "user actions, authentication context or app filter) "
                    "and therefore enforces nothing."
                )

            findings.append(report)

        return findings

    @staticmethod
    def _is_policy_targeted(app_conditions: ApplicationsConditions) -> bool:
        """Determine whether an application conditions block targets at least one resource.

        A policy is considered targeted when any of the following is true:
        - ``included_applications`` contains a non-empty value other than ``"None"``.
        - ``included_user_actions`` is non-empty.
        - ``included_authentication_context_class_references`` is non-empty.
        - ``application_filter_mode`` is set (an application filter is present).

        Args:
            app_conditions: The ``ApplicationsConditions`` object to evaluate.

        Returns:
            True if the policy targets at least one resource, False otherwise.
        """
        # Check included_applications for meaningful values
        has_apps = any(
            app and app != "None"
            for app in (app_conditions.included_applications or [])
        )
        if has_apps:
            return True

        if app_conditions.included_user_actions:
            return True

        if app_conditions.included_authentication_context_class_references:
            return True

        if app_conditions.application_filter_mode is not None:
            return True

        return False
