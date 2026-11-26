"""Check for Conditional Access policy restricting privileged roles to PAWs."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)

# Default privileged role template IDs that should be restricted to PAWs.
# These match the built-in Entra directory roles most commonly targeted in
# Microsoft's privileged access strategy.
DEFAULT_PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
}


class entra_conditional_access_policy_privileged_roles_restricted_to_paw(Check):
    """Check if privileged roles are restricted to Privileged Access Workstations via Conditional Access.

    This check verifies that at least one enabled Conditional Access policy blocks
    access for privileged directory roles from any device that is not a Privileged
    Access Workstation (PAW), targeting all cloud applications and using a device
    filter to scope the restriction.

    - PASS: At least one enabled policy targets the required privileged roles, applies
            to all cloud apps, blocks access, and has a device filter configured.
    - FAIL: No enabled policy meets all the conditions above.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for privileged role PAW restriction.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        privileged_role_ids = set(
            entra_client.audit_config.get(
                "privileged_role_template_ids",
                list(DEFAULT_PRIVILEGED_ROLE_IDS),
            )
        )

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy restricts privileged roles to Privileged Access Workstations (PAWs)."

        # Track which privileged roles are covered across qualifying policies.
        covered_roles: set[str] = set()
        qualifying_policy_names: list[str] = []

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            # The policy must target privileged roles.
            policy_roles = set(policy.conditions.user_conditions.included_roles)
            matched_roles = policy_roles & privileged_role_ids
            if not matched_roles:
                continue

            # Roles explicitly excluded by the policy do not count as covered.
            excluded_roles = set(policy.conditions.user_conditions.excluded_roles)
            matched_roles -= excluded_roles

            if not matched_roles:
                continue

            # Must apply to all cloud applications.
            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            # Policies that exclude applications weaken the coverage.
            if policy.conditions.application_conditions.excluded_applications:
                continue

            # Must block access.
            if (
                ConditionalAccessGrantControl.BLOCK
                not in policy.grant_controls.built_in_controls
            ):
                continue

            # Must have a device filter configured (to scope the block to non-PAW devices).
            device_conditions = policy.conditions.device_conditions
            if (
                not device_conditions
                or not device_conditions.device_filter_mode
                or not device_conditions.device_filter_rule
            ):
                continue

            # Report-only policies do not enforce the restriction.
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                continue

            covered_roles |= matched_roles
            qualifying_policy_names.append(policy.display_name)

        if covered_roles == privileged_role_ids and qualifying_policy_names:
            policy_list = ", ".join(f"'{name}'" for name in qualifying_policy_names)
            report.status = "PASS"
            report.status_extended = (
                f"Conditional Access {'Policy' if len(qualifying_policy_names) == 1 else 'Policies'} "
                f"{policy_list} "
                f"{'restricts' if len(qualifying_policy_names) == 1 else 'restrict'} "
                f"privileged roles to Privileged Access Workstations (PAWs). "
                f"Note: the check verifies that a device filter exists but cannot confirm that the filter rule accurately identifies PAWs."
            )
        elif qualifying_policy_names:
            missing_count = len(privileged_role_ids - covered_roles)
            report.status = "FAIL"
            report.status_extended = (
                f"Conditional Access Policies partially restrict privileged roles to PAWs "
                f"but {missing_count} privileged {'role is' if missing_count == 1 else 'roles are'} not covered."
            )

        findings.append(report)
        return findings
