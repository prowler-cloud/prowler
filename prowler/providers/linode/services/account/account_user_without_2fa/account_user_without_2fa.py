from prowler.lib.check.models import Check, CheckReportLinode
from prowler.providers.linode.services.account.account_client import account_client


class account_user_without_2fa(Check):
    """Check if Linode account users have two-factor authentication enabled."""

    def execute(self) -> list[CheckReportLinode]:
        findings = []

        for user in account_client.users:
            report = CheckReportLinode(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.username,
                resource_id=user.username,
                region="global",
            )

            if user.tfa_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"User '{user.username}' has two-factor authentication enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"User '{user.username}' does not have two-factor authentication enabled."

            findings.append(report)

        return findings
