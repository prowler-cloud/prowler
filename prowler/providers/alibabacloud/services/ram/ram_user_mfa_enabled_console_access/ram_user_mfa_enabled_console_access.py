from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_user_mfa_enabled_console_access(Check):
    """Check if all RAM users with console access have MFA enabled."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for user in ram_client.users:
            # Only check users with console access
            if user.has_console_access:
                report = CheckReportAlibabaCloud(
                    metadata=self.metadata(), resource=user
                )
                report.region = ram_client.region
                report.resource_id = user.name
                report.resource_arn = (
                    f"acs:ram::{ram_client.audited_account}:user/{user.name}"
                )

                # Check if MFA is required for console access
                # mfa_bind_required indicates whether MFA is required in the login profile
                if user.mfa_bind_required:
                    report.status = "PASS"
                    report.status_extended = (
                        f"RAM user {user.name} has MFA enabled for console access."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RAM user {user.name} has console access but does not have MFA enabled."

                findings.append(report)

        return findings
