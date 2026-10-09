"""Check that privileged Microsoft first-party apps require explicit user assignment."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    DEFAULT_PRIVILEGED_FIRST_PARTY_APP_IDS,
    PRIVILEGED_FIRST_PARTY_APP_NAMES,
)


class entra_service_principal_privileged_first_party_assignment_required(Check):
    """Privileged Microsoft first-party apps require explicit user assignment.

    A curated set of Microsoft first-party administration tools (Azure
    PowerShell, Azure CLI, Graph Explorer, etc.) are pre-consented with
    broad delegated permissions.  By default every user can sign in to
    them, giving a compromised account immediate access to powerful
    administrative APIs.

    Setting ``appRoleAssignmentRequired = true`` on each service
    principal restricts sign-in to explicitly assigned users and groups.

    - PASS: The service principal exists and ``appRoleAssignmentRequired``
      is ``true``.
    - FAIL: The service principal does not exist in the tenant, or it
      exists with ``appRoleAssignmentRequired`` set to ``false``.
    - MANUAL: The service principal listing could not be retrieved, or
      ``appRoleAssignmentRequired`` is ``null``/missing in the response.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the privileged first-party assignment check.

        Produces one finding per monitored application ID.

        Returns:
            A list of reports, one per monitored first-party application.
        """
        findings = []

        # If the service-layer fetch failed, emit a single MANUAL finding.
        if entra_client.enterprise_apps_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Privileged First-Party Service Principals",
                resource_id=entra_client.tenant_domain,
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate privileged first-party service principal "
                "assignment: service principal listing could not be retrieved. "
                f"Error: {entra_client.enterprise_apps_error}."
            )
            findings.append(report)
            return findings

        monitored_app_ids = entra_client.audit_config.get(
            "entra_privileged_first_party_app_ids",
            DEFAULT_PRIVILEGED_FIRST_PARTY_APP_IDS,
        )

        # enterprise_apps holds every service principal; look them up by app ID.
        sp_lookup = {
            sp.app_id.lower(): sp
            for sp in (entra_client.enterprise_apps or {}).values()
            if sp.app_id
        }

        for app_id in monitored_app_ids:
            app_id_lower = app_id.lower()
            friendly_name = PRIVILEGED_FIRST_PARTY_APP_NAMES.get(app_id_lower, app_id)
            sp_info = sp_lookup.get(app_id_lower)

            if sp_info is None:
                # Service principal does not exist in the tenant.
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource={},
                    resource_name=friendly_name,
                    resource_id=app_id_lower,
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal for '{friendly_name}' ({app_id_lower}) "
                    f"does not exist in the tenant; Entra creates it on first "
                    f"sign-in with assignment not required, so any user can "
                    f"use it."
                )
                findings.append(report)
                continue

            display_name = sp_info.name or friendly_name

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp_info,
                resource_name=display_name,
                resource_id=sp_info.id,
            )

            if sp_info.app_role_assignment_required is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Service principal '{display_name}' ({app_id_lower}) "
                    f"exists but appRoleAssignmentRequired is null or missing "
                    f"in the Graph response; manual verification is required."
                )
            elif sp_info.app_role_assignment_required:
                report.status = "PASS"
                report.status_extended = (
                    f"Service principal '{display_name}' ({app_id_lower}) "
                    f"requires explicit user assignment "
                    f"(appRoleAssignmentRequired is true)."
                )
            else:
                # appRoleAssignmentRequired is False
                if sp_info.account_enabled is False:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Service principal '{display_name}' ({app_id_lower}) "
                        f"is disabled but assignment is not required; it "
                        f"becomes open to all users if re-enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Service principal '{display_name}' ({app_id_lower}) "
                        f"does not require explicit user assignment and is "
                        f"open to all users."
                    )

            findings.append(report)

        return findings
