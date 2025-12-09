from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_max_login_attempts(Check):
    """Check if RAM password policy temporarily blocks logon after 5 incorrect logon attempts within an hour."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        if ram_client.password_policy:
            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=ram_client.password_policy
            )
            report.region = ram_client.region
            report.resource_id = f"{ram_client.audited_account}-password-policy"
            report.resource_arn = (
                f"acs:ram::{ram_client.audited_account}:password-policy"
            )
            if ram_client.password_policy.max_login_attempts >= 5:
                report.status = "PASS"
                report.status_extended = "RAM password policy temporarily blocks logon after 5 incorrect logon attempts within an hour."
            elif ram_client.password_policy.max_login_attempts == 0:
                report.status = "FAIL"
                report.status_extended = "RAM password policy does not temporarily block logon after incorrect attempts (max login attempts is disabled)."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy temporarily blocks logon after {ram_client.password_policy.max_login_attempts} incorrect logon attempts, which is not the recommended value of 5."

            findings.append(report)

        return findings
