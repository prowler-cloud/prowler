from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_untrusted_locations_blocked(Check):
    """Check if a Conditional Access policy blocks access from untrusted locations.

    At least one enabled Conditional Access policy should target all users and all
    resources, include all network locations, exclude trusted locations, and block
    access, so that access from untrusted locations is denied.

    - PASS: An enabled Conditional Access policy blocks access from untrusted
      locations.
    - FAIL: No Conditional Access policy blocks access from untrusted locations.
    """

    def _excludes_only_trusted(self, exclude_locations, trusted_location_ids) -> bool:
        """Return True if the excluded locations are all trusted."""
        if not exclude_locations:
            return False
        if "AllTrusted" in exclude_locations:
            return True
        return all(
            location_id in trusted_location_ids for location_id in exclude_locations
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
            "No Conditional Access Policy blocks access from untrusted locations."
        )

        trusted_location_ids = {
            location.id
            for location in entra_client.named_locations
            if location.is_trusted
        }

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

            locations = policy.conditions.locations
            if not locations:
                continue

            if "All" not in locations.include_locations:
                continue

            # A trusted-location exclusion must exist so trusted networks keep access.
            if not self._excludes_only_trusted(
                locations.exclude_locations, trusted_location_ids
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                not in policy.grant_controls.built_in_controls
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks untrusted locations but is in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks access from untrusted locations."
                break

        findings.append(report)
        return findings
