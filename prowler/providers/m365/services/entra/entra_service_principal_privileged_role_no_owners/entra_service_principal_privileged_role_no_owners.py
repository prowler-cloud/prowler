from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_service_principal_privileged_role_no_owners(Check):
    """
    Ensure that service principals holding privileged Entra directory roles have no owners.

    An owner of a service principal or its parent app registration can rotate credentials
    and effectively inherit the privileged role, bypassing PIM approval flows and
    Conditional Access policies targeting user accounts.

    - PASS: The service principal has no owners on either itself or its parent app registration.
    - FAIL: The service principal has at least one owner on either itself or its parent app registration.
    - MANUAL: Role assignments or owner data could not be retrieved due to missing permissions.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []

        for tenant, sps in entra_client.service_principals.items():
            # If sps is None, we hit a permissions error fetching role assignments
            if sps is None:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name="Service Principals",
                    resource_id="servicePrincipals",
                )
                report.status = "MANUAL"
                report.status_extended = (
                    "Could not retrieve role assignments or service principal owners. "
                    "Please ensure Directory.Read.All is granted to the Prowler application."
                )
                findings.append(report)
                continue

            # No privileged service principals found — that's compliant
            if not sps:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name="Service Principals",
                    resource_id="servicePrincipals",
                )
                report.status = "PASS"
                report.status_extended = (
                    "No service principals with privileged directory roles were found."
                )
                findings.append(report)
                continue

            for sp_id, sp in sps.items():
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=sp,
                    resource_name=sp.name,
                    resource_id=sp_id,
                )

                all_owners = sp.sp_owner_ids + sp.app_owner_ids

                if all_owners:
                    report.status = "FAIL"
                    roles_str = ", ".join(sp.privileged_roles)
                    owner_count = len(all_owners)
                    report.status_extended = (
                        f"Service principal {sp.name} holds privileged role(s) [{roles_str}] "
                        f"and has {owner_count} owner(s) "
                        f"(SP owners: {len(sp.sp_owner_ids)}, "
                        f"app registration owners: {len(sp.app_owner_ids)})."
                    )
                else:
                    report.status = "PASS"
                    roles_str = ", ".join(sp.privileged_roles)
                    report.status_extended = (
                        f"Service principal {sp.name} holds privileged role(s) [{roles_str}] "
                        f"and has no owners on either the service principal or its parent app registration."
                    )

                findings.append(report)

        return findings