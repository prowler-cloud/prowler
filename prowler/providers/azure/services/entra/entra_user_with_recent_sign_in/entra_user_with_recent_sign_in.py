from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

STALE_THRESHOLD_DAYS = 90


class entra_user_with_recent_sign_in(Check):
    """
    Ensure enabled Entra ID users have signed in within the last 90 days.

    This check evaluates each enabled user's last interactive sign-in to detect stale or dormant accounts that should be reviewed or deprovisioned. Sign-in activity requires Entra ID P1/P2 licensing.

    - PASS: The enabled user signed in within the last 90 days.
    - FAIL: The enabled user has not signed in for more than 90 days, or has no recorded sign-in.
    - MANUAL (tenant-level): Microsoft Graph refused to return sign-in activity for the tenant (missing Entra ID P1/P2 licensing or the AuditLog.Read.All permission), so the check cannot be evaluated; reported once per tenant.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for tenant_domain, users in entra_client.users.items():
            if tenant_domain in entra_client.sign_in_activity_errors:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = tenant_domain
                report.resource_id = entra_client.tenant_ids[0]
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate sign-in activity for tenant {tenant_domain}: "
                    f"Microsoft Graph did not return sign-in activity "
                    f"({entra_client.sign_in_activity_errors[tenant_domain]}). "
                    f"Verify that the tenant has Entra ID P1/P2 licensing and the "
                    f"scanning application has the AuditLog.Read.All permission."
                )
                findings.append(report)
                continue

            enabled_users = {k: v for k, v in users.items() if v.account_enabled}

            for user in enabled_users.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=user)
                report.subscription = f"Tenant: {tenant_domain}"

                if user.last_sign_in is None:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user.name} has no recorded sign-in activity."
                    )
                else:
                    last = user.last_sign_in
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    days_since = (datetime.now(timezone.utc) - last).days
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
