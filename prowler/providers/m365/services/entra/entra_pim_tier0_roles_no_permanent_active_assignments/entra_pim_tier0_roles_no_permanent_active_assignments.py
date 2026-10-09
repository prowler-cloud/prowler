"""Check that Tier 0 roles are held only through PIM just-in-time activation.

Ports the intent of Maester MT.1031 ("Privileged role on Control Plane are
managed by PIM only") using v1.0 ``roleAssignmentScheduleInstances`` data,
aligned with the CIS Microsoft 365 Foundations v7.0 requirement 5.3.1.
"""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
    TIER_0_ROLE_TEMPLATE_IDS,
)
from prowler.providers.m365.services.entra.lib.break_glass import (
    identify_break_glass_user_ids,
)
from prowler.providers.m365.services.entra.lib.pim_licencing import has_pim_licence

# Directory Synchronization Accounts must hold the role permanently and
# cannot be managed via PIM; exclude from evaluation.
PIM_EXEMPT_ROLE_TEMPLATE_IDS = {
    "d29b2b05-8046-44ba-8758-1e26182fcf32",  # Directory Synchronization Accounts
}

# Human-readable names for Tier 0 role template IDs.
TIER_0_ROLE_NAMES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "0526716b-113d-4c15-b2c8-68e3c22b9f80": "Authentication Policy Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Domain Name Administrator",
    "be2f45a1-457d-42af-a067-6ec1fa63bc45": "External Identity Provider Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Partner Tier2 Support",
}


class entra_pim_tier0_roles_no_permanent_active_assignments(Check):
    """Tier 0 directory roles have no standing active assignments.

    This check evaluates whether users and groups hold Control Plane (Tier 0)
    Microsoft Entra roles only through PIM eligibility and just-in-time
    activation. Standing active assignments give full privileges continuously
    and bypass the activation step, MFA, approval, and time limit that PIM
    provides.

    - PASS: The assignment is a PIM just-in-time activation (``Activated``),
      or the principal is an identified break-glass account with a standing
      Global Administrator assignment within the configured maximum count.
    - FAIL: The assignment is a standing active assignment (``Assigned``) to a
      Tier 0 role and the break-glass exception does not apply.
    - MANUAL: PIM is not licensed, or required data could not be retrieved.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the PIM Tier 0 standing assignment check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # --- Licence gate ------------------------------------------------
        pim_licensed = has_pim_licence(entra_client.subscribed_skus)
        if pim_licensed is False:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Tier 0 Role Assignments",
                resource_id="tier0RoleAssignments",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate PIM usage for Tier 0 roles: the tenant has no "
                "Microsoft Entra ID P2 or Microsoft Entra ID Governance licence, "
                "so Privileged Identity Management is not available. All role "
                "assignments are standing assignments."
            )
            findings.append(report)
            return findings

        if entra_client.subscribed_skus_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Tier 0 Role Assignments",
                resource_id="tier0RoleAssignments",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate PIM usage for Tier 0 roles: licence status "
                f"unknown. {entra_client.subscribed_skus_error}."
            )
            findings.append(report)
            return findings

        # --- Data availability gate --------------------------------------
        if entra_client.role_assignment_schedule_instances is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Tier 0 Role Assignments",
                resource_id="tier0RoleAssignments",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate PIM usage for Tier 0 roles: "
                "roleAssignmentScheduleInstances could not be read. "
                "Verify that the RoleAssignmentSchedule.Read.Directory "
                "(or RoleManagement.Read.Directory) permission is granted "
                "to the scanning application."
            )
            findings.append(report)
            return findings

        # --- Break-glass identification ----------------------------------
        max_break_glass_ga = entra_client.audit_config.get(
            "max_permanent_break_glass_global_admins", 2
        )
        configured_emergency_ids = entra_client.audit_config.get(
            "emergency_access_user_ids", []
        )

        break_glass_ids = identify_break_glass_user_ids(
            entra_client.conditional_access_policies,
            configured_emergency_ids,
        )
        ca_unavailable = break_glass_ids is None
        if ca_unavailable:
            break_glass_ids = set(configured_emergency_ids or [])

        # --- Scope the Tier 0 roles to evaluate -------------------------
        scoped_tier0_ids = TIER_0_ROLE_TEMPLATE_IDS - PIM_EXEMPT_ROLE_TEMPLATE_IDS

        # --- Filter instances to evaluate --------------------------------
        evaluated_instances = [
            inst
            for inst in entra_client.role_assignment_schedule_instances
            if inst.role_definition_id in scoped_tier0_ids
            and inst.member_type == "Direct"
            and inst.principal_odata_type
            in (
                "#microsoft.graph.user",
                "#microsoft.graph.group",
            )
        ]

        if not evaluated_instances:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Tier 0 Role Assignments",
                resource_id="tier0RoleAssignments",
            )
            report.status = "PASS"
            report.status_extended = (
                "No active Tier 0 role assignment instances found for "
                "users or groups."
            )
            findings.append(report)
            return findings

        # Count break-glass users with standing GA assignments for the
        # threshold check.
        break_glass_ga_assigned_count = sum(
            1
            for inst in evaluated_instances
            if inst.assignment_type == "Assigned"
            and inst.role_definition_id == GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID
            and inst.principal_odata_type == "#microsoft.graph.user"
            and inst.principal_id in break_glass_ids
        )

        # --- Evaluate each instance --------------------------------------
        for inst in evaluated_instances:
            role_name = TIER_0_ROLE_NAMES.get(
                inst.role_definition_id, inst.role_definition_id
            )
            scope_display = (
                "tenant-wide"
                if inst.directory_scope_id == "/"
                else inst.directory_scope_id
            )
            is_user = inst.principal_odata_type == "#microsoft.graph.user"
            principal_type = "User" if is_user else "Group"

            # Build the resource name following the ticket spec.
            resource_name = (
                f"{inst.principal_display_name} - {role_name} ({scope_display})"
            )

            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name=resource_name,
                resource_id=inst.id,
            )

            if inst.assignment_type == "Activated":
                # PIM just-in-time activation -> PASS
                report.status = "PASS"
                report.status_extended = (
                    f"{principal_type} '{inst.principal_display_name}' "
                    f"has a PIM just-in-time activation for Tier 0 role "
                    f"{role_name} ({scope_display})."
                )
                findings.append(report)
                continue

            # Standing active assignment (Assigned).
            is_permanent = inst.end_date_time is None
            duration_desc = (
                "permanent"
                if is_permanent
                else f"time-bound until {inst.end_date_time.isoformat()}"
            )

            # Check break-glass exception (users only, GA only, within cap).
            if (
                is_user
                and inst.principal_id in break_glass_ids
                and inst.role_definition_id == GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID
                and break_glass_ga_assigned_count <= max_break_glass_ga
            ):
                report.status = "PASS"
                upn_part = f" ({inst.principal_upn})" if inst.principal_upn else ""
                report.status_extended = (
                    f"{principal_type} '{inst.principal_display_name}'"
                    f"{upn_part} has a standing {duration_desc} assignment to "
                    f"Tier 0 role {role_name} ({scope_display}) and is "
                    f"accepted as an emergency-access (break-glass) account "
                    f"({break_glass_ga_assigned_count} of "
                    f"{max_break_glass_ga} allowed)."
                )
                findings.append(report)
                continue

            # FAIL: standing active assignment without exception.
            report.status = "FAIL"
            upn_part = (
                f" ({inst.principal_upn})" if is_user and inst.principal_upn else ""
            )
            report.status_extended = (
                f"{principal_type} '{inst.principal_display_name}'"
                f"{upn_part} has a standing {duration_desc} assignment to "
                f"Tier 0 role {role_name} ({scope_display}) instead of a "
                f"PIM eligible assignment."
            )
            if ca_unavailable:
                report.status_extended = (
                    report.status_extended[:-1]
                    + " (emergency-access accounts could not be identified: "
                    "Conditional Access policies unavailable)."
                )
            findings.append(report)

        return findings
