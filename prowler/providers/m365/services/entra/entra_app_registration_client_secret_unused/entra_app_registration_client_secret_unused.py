from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_app_registration_client_secret_unused(Check):
    """
    Ensure that application registrations do not use password credentials (client secrets).

    This check evaluates application registrations in Microsoft Entra ID to identify
    those with password credentials (client secrets). Applications should authenticate
    using certificates, federated identity credentials, or managed identities instead.
    Both expired and active password credentials are flagged, since expired entries are
    credential clutter that should be cleaned up.

    - PASS: The application has no password credentials.
    - FAIL: The application has one or more password credentials that should be removed.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []

        for app_id, app in entra_client.app_registrations.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name or app.app_id,
                resource_id=app_id,
            )

            num_secrets = len(app.password_credentials)
            if num_secrets > 0:
                report.status = "FAIL"
                secret_details = []
                for cred in app.password_credentials:
                    detail = cred.display_name or cred.key_id
                    if cred.end_date_time:
                        detail += f" (expires: {cred.end_date_time})"
                    secret_details.append(detail)

                if num_secrets > 5:
                    displayed = ", ".join(secret_details[:5])
                    displayed += f" (and {num_secrets - 5} more)"
                else:
                    displayed = ", ".join(secret_details)

                report.status_extended = (
                    f"App registration {app.name} has {num_secrets} "
                    f"password credential(s) (client secrets): {displayed}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration {app.name} does not use password credentials."
                )

            findings.append(report)

        return findings
