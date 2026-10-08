"""Check for privileged service principals without accountable owners."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PRIVILEGED_NON_TIER0_ROLE_TEMPLATE_IDS,
)


class entra_service_principal_privileged_permissions_no_owners(Check):
    """Service principals with privileged permissions must have at least one owner.

    Non-Microsoft service principals that hold privileged permissions
    (application permissions, admin-consented delegated permissions, or
    privileged non-Tier-0 directory roles) must have at least one owner on
    either the service principal or on its parent application registration.

    Service principals holding Tier 0 directory roles are excluded because
    they are already covered by
    ``entra_service_principal_privileged_role_no_owners``.

    - PASS: The service principal holds privileged permissions and has at
      least one owner on the service principal or its parent app
      registration.
    - FAIL: The service principal holds privileged permissions and has no
      owners on either the service principal or the parent app
      registration.
    - MANUAL: Service principal data could not be retrieved.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the privileged-permission owner accountability check.

        Returns:
            A list of reports, one per service principal that holds
            privileged permissions.
        """
        findings: List[CheckReportM365] = []

        # If the service layer could not retrieve data, emit a single
        # MANUAL finding so the user knows the check could not run.
        if entra_client.privileged_permission_service_principals_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Service Principals",
                resource_id=entra_client.tenant_domain,
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate privileged permissions for service "
                "principals: "
                f"{entra_client.privileged_permission_service_principals_error}. "
                "Verify that the scanning application has "
                "Application.Read.All, DelegatedPermissionGrant.Read.All, "
                "and RoleManagement.Read.Directory permissions."
            )
            findings.append(report)
            return findings

        for sp in entra_client.privileged_permission_service_principals.values():
            # Build a human-readable list of all privileged permissions.
            all_privileged: List[str] = []
            all_privileged.extend(sp.privileged_app_permissions)
            all_privileged.extend(sp.privileged_delegated_permissions)
            all_privileged.extend(
                PRIVILEGED_NON_TIER0_ROLE_TEMPLATE_IDS.get(role_id, role_id)
                for role_id in sp.privileged_directory_role_ids
            )

            if not all_privileged:
                # Defensive: the service should only store SPs with
                # privileges, but guard against unexpected empties.
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp,
                resource_name=sp.name,
                resource_id=sp.id,
            )

            unique_owners = set(sp.sp_owner_ids) | set(sp.app_owner_ids)
            permissions_label = ", ".join(sorted(set(all_privileged)))

            if unique_owners:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds privileged "
                    f"permissions ({permissions_label}) and has "
                    f"{len(unique_owners)} owner(s) "
                    f"({len(sp.sp_owner_ids)} on the service principal, "
                    f"{len(sp.app_owner_ids)} on the parent app "
                    f"registration)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds privileged "
                    f"permissions ({permissions_label}) and has no owners "
                    f"on either the service principal or its parent app "
                    f"registration."
                )

            findings.append(report)

        return findings
