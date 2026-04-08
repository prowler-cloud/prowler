from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)


class entra_conditional_access_policy_approved_client_app_required_for_mobile(Check):
    """Check if a Conditional Access policy requires approved client apps or app protection for mobile devices.

    This check ensures that at least one enabled Conditional Access policy
    targets iOS and Android platforms and requires approved client apps or
    app protection policies.
    - PASS: An enabled policy requires approved client apps or app protection for iOS/Android.
    - FAIL: No policy restricts mobile app access to approved or protected apps.
    """

    REQUIRED_MOBILE_PLATFORMS = {"android", "ios"}
    MOBILE_APP_GRANT_CONTROLS = {
        ConditionalAccessGrantControl.APPROVED_APPLICATION,
        ConditionalAccessGrantControl.COMPLIANT_APPLICATION,
    }

    @staticmethod
    def _normalize_platform(platform: object) -> str:
        normalized_platform = getattr(platform, "value", platform)
        return (
            normalized_platform.lower() if isinstance(normalized_platform, str) else ""
        )

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
        report.status_extended = "No Conditional Access Policy requires approved client apps or app protection for mobile devices."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.conditions.platform_conditions:
                continue

            included_platforms = {
                normalized_platform
                for normalized_platform in map(
                    self._normalize_platform,
                    policy.conditions.platform_conditions.include_platforms,
                )
                if normalized_platform
            }
            excluded_platforms = {
                normalized_platform
                for normalized_platform in map(
                    self._normalize_platform,
                    policy.conditions.platform_conditions.exclude_platforms,
                )
                if normalized_platform
            }

            targets_mobile_platforms = (
                "all" in included_platforms
                or self.REQUIRED_MOBILE_PLATFORMS.issubset(included_platforms)
            ) and not (
                "all" in excluded_platforms
                or self.REQUIRED_MOBILE_PLATFORMS.intersection(excluded_platforms)
            )
            if not targets_mobile_platforms:
                continue

            built_in_controls = set(policy.grant_controls.built_in_controls)
            has_mobile_app_control = bool(
                self.MOBILE_APP_GRANT_CONTROLS.intersection(built_in_controls)
            )
            if not has_mobile_app_control:
                continue

            if (
                policy.grant_controls.operator == GrantControlOperator.OR
                and not built_in_controls.issubset(self.MOBILE_APP_GRANT_CONTROLS)
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports the requirement of approved client apps or app protection for mobile devices but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires approved client apps or app protection for mobile devices."
                break

        findings.append(report)

        return findings
