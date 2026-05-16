"""Check for service principals with privileged roles that have owners."""
from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import TIER_0_ROLE_TEMPLATE_IDS


class entra_service_principal_privileged_role_no_owners(Check):
    """
    Service principals with privileged Entra directory roles must have no owners.

    An owner of a service principal or its parent app registration can rotate
    credentials and inherit the SP's privileges — entirely outside PIM approval
    flows and Conditional Access policies targeting user accounts.

    - PASS: The privileged service principal has zero owners on both the SP
      and its parent app registration.
    - FAIL: The privileged service principal has at least one owner on either
      the SP or its parent app registration.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the privileged service principal owner check.

        Returns:
            A list of reports containing the result of the check for each
            privileged service principal.
        """
        findings = []
        for sp in entra_client.service_principals.values():
            tier0_roles = [
                role_id
                for role_id in sp.directory_role_template_ids
                if role_id in TIER_0_ROLE_TEMPLATE_IDS
            ]

            if not tier0_roles:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp,
                resource_name=sp.name,
                resource_id=sp.id,
            )

            all_owners = sp.sp_owner_ids + sp.app_owner_ids

            if all_owners:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds {len(tier0_roles)} "
                    f"privileged directory role(s) and has {len(all_owners)} "
                    f"owner(s) (SP owners: {sp.sp_owner_ids}, "
                    f"app owners: {sp.app_owner_ids})."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{sp.name}' holds privileged directory "
                    f"role(s) and has no owners on either the service principal "
                    f"or its parent app registration."
                )

            findings.append(report)
        return findings
