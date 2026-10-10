"""Check that no external (guest) user holds a standing Tier 0 directory role."""

from types import SimpleNamespace
from typing import List, Optional

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    TIER_0_ROLE_NAMES,
    TIER_0_ROLE_TEMPLATE_IDS,
)


def _is_external_user(user) -> bool:
    """Determine whether a user is an external (B2B) identity.

    A user is considered external when:
    - ``user_type`` is ``Guest`` (case-insensitive), or
    - ``user_principal_name`` contains ``#EXT#`` (case-insensitive),
      which catches B2B users converted to Member.

    Args:
        user: An ``entra_service.User`` instance.

    Returns:
        True if the user is an external identity.
    """
    if user.user_type and user.user_type.lower() == "guest":
        return True
    if user.user_principal_name and "#ext#" in user.user_principal_name.lower():
        return True
    return False


class entra_guest_users_no_permanent_tier0_roles(Check):
    """No external (guest) user holds a standing Tier 0 directory role assignment.

    This check evaluates whether any external (B2B guest) user has a standing
    (non-just-in-time) active assignment to a Control Plane / Tier 0 Microsoft
    Entra directory role, either directly or through a role-assignable group.

    - PASS: No external user holds a standing Tier 0 role assignment.
    - FAIL: An external user holds at least one standing Tier 0 role assignment.
    - MANUAL: Role assignment schedule instances or users could not be read.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the guest Tier 0 role assignment check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # --- Guard: role assignment data unavailable --------------------------
        if entra_client.role_assignment_schedule_instances is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Guest Tier 0 role assignments",
                resource_id="guestTier0Assignments",
            )
            report.status = "MANUAL"
            report.status_extended = (
                entra_client.role_assignment_schedule_instances_error
                or (
                    "Cannot evaluate guest Tier 0 role assignments: role "
                    "assignment schedule instances could not be retrieved."
                )
            )
            findings.append(report)
            return findings

        # --- Guard: user directory unavailable --------------------------------
        if entra_client.users_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Guest Tier 0 role assignments",
                resource_id="guestTier0Assignments",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate guest Tier 0 role assignments: user "
                "directory could not be read. "
                f"{entra_client.users_error}"
            )
            findings.append(report)
            return findings

        # --- Build lookup structures ------------------------------------------
        groups_by_id = {g.id: g for g in entra_client.groups}

        # Filter to standing Tier 0 instances only
        standing_tier0_instances = [
            inst
            for inst in entra_client.role_assignment_schedule_instances
            if inst.assignment_type == "Assigned"
            and inst.role_definition_id in TIER_0_ROLE_TEMPLATE_IDS
        ]

        # --- Evaluate each standing Tier 0 instance --------------------------
        fail_found = False

        for inst in standing_tier0_instances:
            role_name = TIER_0_ROLE_NAMES.get(
                inst.role_definition_id, inst.role_definition_id
            )
            scope_label = (
                "tenant-wide"
                if inst.directory_scope_id == "/"
                else inst.directory_scope_id
            )

            # Check if the principal is a user directly
            user = entra_client.users.get(inst.principal_id)
            if user and _is_external_user(user):
                fail_found = True
                findings.append(
                    self._build_fail_report(
                        user=user,
                        role_name=role_name,
                        scope_label=scope_label,
                        end_date_time=inst.end_date_time,
                        group_name=None,
                    )
                )
                continue

            # If the principal is a role-assignable group, resolve members
            group = groups_by_id.get(inst.principal_id)
            is_group_principal = (
                inst.principal_odata_type or ""
            ).lower() == "#microsoft.graph.group"
            if is_group_principal and group is None:
                # The /groups listing may have failed; the assignment still
                # tells us the principal is a group.
                group = SimpleNamespace(
                    id=inst.principal_id,
                    name=inst.principal_display_name or inst.principal_id,
                )
            if is_group_principal or (group and group.is_assignable_to_role):
                member_findings = self._evaluate_group_members(
                    group=group,
                    role_name=role_name,
                    scope_label=scope_label,
                    end_date_time=inst.end_date_time,
                )
                if member_findings is None:
                    # Could not read group members -> MANUAL for this group
                    report = CheckReportM365(
                        metadata=self.metadata(),
                        resource={},
                        resource_name=f"Group {group.name}",
                        resource_id=group.id,
                    )
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Members of group '{group.name}' holding Tier 0 role "
                        f"{role_name} ({scope_label}) could not be read."
                    )
                    findings.append(report)
                else:
                    if member_findings:
                        fail_found = True
                    findings.extend(member_findings)

        # --- Tenant-level PASS if no FAIL findings ----------------------------
        if not fail_found:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Guest Tier 0 role assignments",
                resource_id="guestTier0Assignments",
            )
            report.status = "PASS"
            report.status_extended = (
                "No external user holds a standing Tier 0 role assignment."
            )
            findings.append(report)

        return findings

    def _build_fail_report(
        self,
        user,
        role_name: str,
        scope_label: str,
        end_date_time,
        group_name: Optional[str] = None,
    ) -> CheckReportM365:
        """Build a FAIL finding for an external user with a standing Tier 0 role.

        Args:
            user: The ``entra_service.User`` holding the role.
            role_name: The display name of the Tier 0 role.
            scope_label: Human-readable scope (``tenant-wide`` or the scope id).
            end_date_time: The assignment expiry, or ``None`` for permanent.
            group_name: If inherited through a group, the group's display name.

        Returns:
            A FAIL CheckReportM365.
        """
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name=user.name or user.id,
            resource_id=user.id,
        )
        report.status = "FAIL"

        upn = user.user_principal_name or "unknown"
        user_type = user.user_type or "unknown"
        duration = (
            "permanent"
            if end_date_time is None
            else f"time-bound until {end_date_time.isoformat()}"
        )
        via_group = f" via group '{group_name}'" if group_name else ""

        report.status_extended = (
            f"{user_type.capitalize()} user '{user.name}' "
            f"({upn}) has a standing {duration} assignment to the "
            f"Tier 0 role {role_name} ({scope_label}){via_group}."
        )
        return report

    def _evaluate_group_members(
        self,
        group,
        role_name: str,
        scope_label: str,
        end_date_time,
    ) -> Optional[List[CheckReportM365]]:
        """Check group members for external users inheriting a Tier 0 role.

        Args:
            group: The ``entra_service.Group`` that holds the role assignment.
            role_name: The display name of the Tier 0 role.
            scope_label: Human-readable scope.
            end_date_time: The assignment expiry.

        Returns:
            A list of FAIL reports for external users found in the group,
            an empty list if no external users found, or ``None`` if group
            members could not be read.
        """
        member_reports = []
        members = entra_client.tier0_role_group_members.get(group.id)
        if members is None:
            return None

        for member_id in members:
            user = entra_client.users.get(member_id)
            if user and _is_external_user(user):
                member_reports.append(
                    self._build_fail_report(
                        user=user,
                        role_name=role_name,
                        scope_label=scope_label,
                        end_date_time=end_date_time,
                        group_name=group.name,
                    )
                )

        return member_reports
