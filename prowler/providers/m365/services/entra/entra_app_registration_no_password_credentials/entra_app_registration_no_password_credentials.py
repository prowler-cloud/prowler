from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_app_registration_no_password_credentials(Check):
    """Ensure application registrations do not use password credentials (client secrets).

    Customer-owned applications should authenticate using certificates, federated
    identity credentials, or managed identities instead of long-lived shared secrets.

    - PASS: The application has no password credentials.
    - FAIL: The application has one or more password credentials.
    """

    def execute(self) -> list[CheckReportM365]:
        findings = []

        if not entra_client.app_registrations:
            return findings

        for app in entra_client.app_registrations.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name,
                resource_id=app.id,
            )

            if app.password_credentials:
                count = len(app.password_credentials)
                report.status = "FAIL"
                report.status_extended = (
                    f"App registration '{app.name}' (appId: {app.app_id}) "
                    f"has {count} password credential(s) (client secret(s)). "
                    f"Migrate to certificates or federated identity credentials."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration '{app.name}' (appId: {app.app_id}) "
                    f"does not use password credentials."
                )

            findings.append(report)

        return findings
