"""Check for service principals with privileged roles that have owners."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_service_principal_privileged_role_no_owners(Check):
    """Service principal with a permanent Tier 0 directory role has no owners.

    Owners of a service principal or its parent app registration can rotate
    credentials and sign in as the service principal, inheriting its privileged
    directory role outside PIM approval flows and Conditional Access policies
    targeting user accounts.

    - PASS: The service principal does not hold a permanent Tier 0 directory
      role, or it does but has zero owners on both the service principal and
      its parent app registration.
    - FAIL: The service principal holds a permanent Tier 0 directory role and
      has at least one owner on either the service principal or its parent
      app registration.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the privileged service principal owner check.

        Returns:
            A list of reports, one per service principal owned by the audited
            tenant.
        """
        findings = []
        for sp in entra_client.service_principals.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp,
                resource_name=sp.name,
                resource_id=sp.id,
            )

            if not sp.directory_role_template_ids:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{sp.name}' has no permanent Tier 0 "
                    f"directory role assignments."
                )
                findings.append(report)
                continue

            unique_owners = set(sp.sp_owner_ids) | set(sp.app_owner_ids)
            tier0_role_count = len(sp.directory_role_template_ids)

            if unique_owners:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds {tier0_role_count} "
                    f"permanent Tier 0 directory role(s) and has "
                    f"{len(unique_owners)} owner(s) "
                    f"({len(sp.sp_owner_ids)} on the service principal, "
                    f"{len(sp.app_owner_ids)} on the parent app registration)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds {tier0_role_count} "
                    f"permanent Tier 0 directory role(s) and has no owners on "
                    f"either the service principal or its parent app registration."
                )

            findings.append(report)
        return findings
