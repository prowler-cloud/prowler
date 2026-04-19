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

            # Detect license issue: if ALL enabled users have no sign-in data,
            # signInActivity is likely unavailable (requires Entra ID P1/P2).
            # Report a single warning instead of mass false positives.
            all_null = all(
                u.last_sign_in is None for u in enabled_users.values()
            )
            if all_null and len(enabled_users) > 1:
                first_user = next(iter(enabled_users.values()))
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=first_user
                )
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = "Sign-in Activity Data"
                report.status = "FAIL"
                report.status_extended = (
                    f"No sign-in activity data available for any of the "
                    f"{len(enabled_users)} enabled users. This likely means "
                    f"the tenant does not have an Entra ID P1/P2 license."
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
