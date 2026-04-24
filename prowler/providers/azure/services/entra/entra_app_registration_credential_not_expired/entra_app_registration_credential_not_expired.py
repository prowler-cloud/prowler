from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

EXPIRY_WARNING_DAYS = 30


class entra_app_registration_credential_not_expired(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, apps in entra_client.app_registrations.items():
            for app_id, app in apps.items():
                if not app.credentials:
                    continue

                for credential in app.credentials:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=app
                    )
                    report.subscription = f"Tenant: {tenant_domain}"
                    report.resource_name = (
                        f"{app.name} ({credential.credential_type}: "
                        f"{credential.display_name or 'unnamed'})"
                    )

                    if credential.end_date_time is None:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"App '{app.name}' has a {credential.credential_type} "
                            f"credential with no expiration date."
                        )
                    else:
                        now = datetime.now(timezone.utc)
                        end = credential.end_date_time
                        if end.tzinfo is None:
                            end = end.replace(tzinfo=timezone.utc)
                        if end <= now:
                            days_ago = (now - end).days
                            report.status = "FAIL"
                            report.status_extended = (
                                f"App '{app.name}' has a {credential.credential_type} "
                                f"credential that expired {days_ago} days ago."
                            )
                        elif (end - now).days <= EXPIRY_WARNING_DAYS:
                            days_left = (end - now).days
                            report.status = "FAIL"
                            report.status_extended = (
                                f"App '{app.name}' has a {credential.credential_type} "
                                f"credential expiring in {days_left} days."
                            )
                        else:
                            days_left = (end - now).days
                            report.status = "PASS"
                            report.status_extended = (
                                f"App '{app.name}' has a {credential.credential_type} "
                                f"credential valid for {days_left} more days."
                            )

                    findings.append(report)

        return findings
