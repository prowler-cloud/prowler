"""Check for Conditional Access policy blocking unknown or unsupported device platforms."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_block_unknown_device_platforms(Check):
    """Ensure a Conditional Access policy blocks access from unknown or unsupported device platforms.

    This check verifies that at least one enabled Conditional Access policy
    blocks access when the device platform is unknown or unsupported. The
    recommended configuration includes all device platforms and excludes the
    known platforms (Android, iOS, Windows, macOS, Linux), so only
    unrecognised platforms are blocked.

    - PASS: An enabled policy blocks access from unknown or unsupported device platforms.
    - FAIL: No policy blocks access from unknown or unsupported device platforms.
    """

    KNOWN_PLATFORMS = {"android", "ios", "windows", "macos", "linux"}

    def _is_candidate_policy(self, policy: ConditionalAccessPolicy) -> bool:
        """Determine whether a policy is a candidate for blocking unknown device platforms.

        A candidate policy must:
        - Not be disabled.
        - Have platform conditions configured.
        - Include all platforms.
        - Exclude all known platforms so only unknown ones are affected.
        - Use the block grant control.

        Args:
            policy: The Conditional Access policy to evaluate.

        Returns:
            True if the policy is a candidate, False otherwise.
        """
        if policy.state == ConditionalAccessPolicyState.DISABLED:
            return False

        if not policy.conditions.platform_conditions:
            return False

        included_platforms = set(
            policy.conditions.platform_conditions.include_platforms
        )

        if "all" not in included_platforms:
            return False

        excluded_platforms = set(
            policy.conditions.platform_conditions.exclude_platforms
        )

        if not self.KNOWN_PLATFORMS.issubset(excluded_platforms):
            return False

        if (
            ConditionalAccessGrantControl.BLOCK
            not in policy.grant_controls.built_in_controls
        ):
            return False

        return True

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
        report.status_extended = "No Conditional Access Policy blocks access from unknown or unsupported device platforms."

        for policy in entra_client.conditional_access_policies.values():
            if not self._is_candidate_policy(policy):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy {policy.display_name} reports "
                    "blocking unknown or unsupported device platforms but does not enforce it."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy {policy.display_name} blocks "
                    "access from unknown or unsupported device platforms."
                )
                break

        findings.append(report)
        return findings
