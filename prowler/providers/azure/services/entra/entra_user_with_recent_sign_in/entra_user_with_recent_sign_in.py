from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

STALE_THRESHOLD_DAYS = 90


class entra_user_with_recent_sign_in(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, users in entra_client.users.items():
            enabled_users = {
                k: v for k, v in users.items() if v.account_enabled
            }

            if not enabled_users:
                continue

            # If all enabled users are missing sign-in data, avoid claiming
            # they never signed in. This usually indicates missing telemetry,
            # often due to licensing or Graph permission limitations.
            all_null = all(
                u.last_sign_in is None for u in enabled_users.values()
            )
            if all_null:
                first_user = next(iter(enabled_users.values()))
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=first_user
                )
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = "Sign-in Activity Data"
                count = len(enabled_users)
                noun = "user" if count == 1 else "users"
                report.status = "FAIL"
                report.status_extended = (
                    f"No sign-in activity data available for any of the "
                    f"{count} enabled {noun}. This likely means the tenant "
                    f"is missing Entra ID P1/P2 licensing or the required "
                    f"Graph permissions to read sign-in activity."
                )
                findings.append(report)
                continue

            for user_domain_name, user in enabled_users.items():
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
                    last = user.last_sign_in
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    days_since = (
                        datetime.now(timezone.utc) - last
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
