"""Check that non-Microsoft enterprise applications require explicit user assignment."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    MICROSOFT_FIRST_PARTY_TENANT_IDS,
)


class entra_service_principal_non_microsoft_assignment_required(Check):
    """Ensure non-Microsoft enterprise applications require explicit user assignment.

    This check evaluates every enabled, non-Microsoft enterprise application
    (service principal of type Application or Legacy) and verifies that the
    ``appRoleAssignmentRequired`` property is set to ``True``. When it is
    ``False``, any user in the tenant (including guests) can sign in to the
    application without being explicitly assigned, widening the blast radius
    of any account takeover.

    - PASS: ``appRoleAssignmentRequired`` is ``True``, or the service
      principal is disabled (``accountEnabled`` is ``False``).
    - FAIL: The service principal is enabled and ``appRoleAssignmentRequired``
      is ``False``.
    - MANUAL: The enterprise application list could not be retrieved, or an
      individual service principal's assignment/enabled state is
      indeterminate.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the assignment-required check for non-Microsoft enterprise apps.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # If the enterprise apps data could not be retrieved, emit one
        # tenant-level MANUAL finding.
        if entra_client.enterprise_apps is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Enterprise applications",
                resource_id="servicePrincipals",
            )
            report.status = "MANUAL"
            error_detail = entra_client.enterprise_apps_error or "unknown error"
            report.status_extended = (
                "Cannot evaluate enterprise application assignment settings: "
                f"the service principal list could not be retrieved ({error_detail}). "
                "Verify that Directory.Read.All is granted to the scanning application."
            )
            findings.append(report)
            return findings

        excluded_app_ids: set[str] = {
            app_id.lower()
            for app_id in (
                entra_client.audit_config.get(
                    "entra_assignment_required_excluded_app_ids", []
                )
                or []
            )
        }

        for sp in entra_client.enterprise_apps.values():
            # Only evaluate Application and Legacy types (skip
            # ManagedIdentity, SocialIdp, and any other types).
            if sp.service_principal_type not in ("Application", "Legacy"):
                continue

            # Skip Microsoft first-party service principals.
            if (
                sp.app_owner_organization_id
                and sp.app_owner_organization_id in MICROSOFT_FIRST_PARTY_TENANT_IDS
            ):
                continue

            # Skip apps explicitly excluded by configuration.
            if sp.app_id and sp.app_id.lower() in excluded_app_ids:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp,
                resource_name=sp.name or sp.app_id or sp.id,
                resource_id=sp.id,
            )

            # When the assignment-required value is indeterminate, or
            # accountEnabled is null while assignment is not required, emit
            # MANUAL for this individual service principal.
            if sp.app_role_assignment_required is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Enterprise application '{sp.name}' (appId {sp.app_id}) "
                    "has an indeterminate appRoleAssignmentRequired value; "
                    "the assignment state cannot be evaluated."
                )
                findings.append(report)
                continue

            if sp.app_role_assignment_required:
                # Assignment is required — compliant.
                report.status = "PASS"
                report.status_extended = (
                    f"Enterprise application '{sp.name}' (appId {sp.app_id}) "
                    "requires explicit user assignment."
                )
            elif not sp.account_enabled:
                # Disabled SPs cannot be signed into, so PASS, but note that
                # the setting is still off.
                report.status = "PASS"
                report.status_extended = (
                    f"Enterprise application '{sp.name}' (appId {sp.app_id}) "
                    "is disabled and does not require user assignment. "
                    "If re-enabled, any user in the tenant would be able to "
                    "sign in to it."
                )
            else:
                # Enabled and assignment not required — non-compliant.
                report.status = "FAIL"
                report.status_extended = (
                    f"Enterprise application '{sp.name}' (appId {sp.app_id}) "
                    "does not require user assignment: any user in the tenant "
                    "can sign in to it."
                )

            findings.append(report)

        return findings
