from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

STALE_THRESHOLD_DAYS = 90


class entra_user_with_recent_sign_in(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, users in entra_client.users.items():
            for user_domain_name, user in users.items():
                if not user.account_enabled:
                    continue

                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=user
                )
                report.subscription = f"Tenant: {tenant_domain}"

                if user.last_sign_in is None:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user.name} has never signed in."
                    )
                else:
                    days_since = (
                        datetime.now(timezone.utc) - user.last_sign_in
                    ).days
                    if days_since > STALE_THRESHOLD_DAYS:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"User {user.name} has not signed in for {days_since} days."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"User {user.name} signed in {days_since} days ago."
                        )

                findings.append(report)

        return findings
