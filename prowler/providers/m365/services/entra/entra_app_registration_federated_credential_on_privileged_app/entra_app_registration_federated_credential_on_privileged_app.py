from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    TIER_0_ROLE_TEMPLATE_IDS,
)


class entra_app_registration_federated_credential_on_privileged_app(Check):
    """
    Application registrations with a privileged role should not have federated
    identity credentials.

    A federated identity credential (workload identity federation) grants an
    external OpenID Connect issuer/subject pair standing token exchange against
    the application, with no stored secret and no expiry. When the same
    application's service principal also holds a Control Plane (Tier 0) directory
    role, an external CI system (GitHub Actions, GitLab CI, etc.) can mint tokens
    that act with those privileged rights, and the trust boundary lives entirely
    in the external provider's account/repository namespace.

    The check joins application registrations (which own the federated identity
    credentials) with their service principal's permanent Tier 0 role
    assignments, reusing the privileged model of
    ``entra_service_principal_no_secrets_for_permanent_tier0_roles``.

    - PASS: The application has no federated identity credentials, or has them
      while holding no privileged (Tier 0) directory role.
    - FAIL: The application has at least one federated identity credential and a
      permanent assignment to at least one Control Plane (Tier 0) directory role.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []

        # Map each application (client) ID to the permanent Tier 0 (Control
        # Plane) directory roles its service principal holds. Federated identity
        # credentials live on the /applications object while directory role
        # assignments live on the service principal, so the two are joined by
        # appId. Building the map once keeps the per-application lookup O(1).
        tier0_roles_by_app_id = {}
        for sp in entra_client.service_principals.values():
            if not sp.app_id:
                continue
            tier0_roles = [
                role_id
                for role_id in sp.directory_role_template_ids
                if role_id in TIER_0_ROLE_TEMPLATE_IDS
            ]
            if tier0_roles:
                tier0_roles_by_app_id.setdefault(sp.app_id, []).extend(tier0_roles)

        for object_id, app in entra_client.app_registrations.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name or app.app_id,
                resource_id=object_id,
            )

            federated_credentials = app.federated_identity_credentials
            tier0_roles = tier0_roles_by_app_id.get(app.app_id, [])

            if federated_credentials and tier0_roles:
                report.status = "FAIL"
                num_credentials = len(federated_credentials)
                credential_details = [
                    f"{cred.name or 'unnamed'} (issuer: {cred.issuer or 'n/a'}, "
                    f"subject: {cred.subject or 'n/a'})"
                    for cred in federated_credentials
                ]
                if num_credentials > 5:
                    displayed = ", ".join(credential_details[:5])
                    displayed += f" (and {num_credentials - 5} more)"
                else:
                    displayed = ", ".join(credential_details)

                report.status_extended = (
                    f"App registration {app.name} holds {num_credentials} federated "
                    f"identity credential(s) and a permanent assignment to "
                    f"{len(tier0_roles)} Control Plane (Tier 0) directory role(s), so "
                    f"external workloads can obtain privileged tokens: {displayed}."
                )
            elif federated_credentials:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration {app.name} holds "
                    f"{len(federated_credentials)} federated identity credential(s) "
                    f"but no privileged (Tier 0) directory role."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration {app.name} has no federated identity "
                    f"credentials."
                )

            findings.append(report)

        return findings
