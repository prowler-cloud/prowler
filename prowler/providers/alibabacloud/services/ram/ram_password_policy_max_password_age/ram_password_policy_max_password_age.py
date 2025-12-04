from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_max_password_age(Check):
    """Check if RAM password policy expires passwords in 365 days or greater."""

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

            # If max_password_age is 0, it means password expiration is disabled (which is acceptable)
            # If it's set, it should be 365 or greater
            if ram_client.password_policy.max_password_age == 0:
                report.status = "PASS"
                report.status_extended = "RAM password policy does not expire passwords (password expiration is disabled)."
            elif ram_client.password_policy.max_password_age >= 365:
                report.status = "PASS"
                report.status_extended = f"RAM password policy expires passwords after {ram_client.password_policy.max_password_age} days."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy expires passwords after {ram_client.password_policy.max_password_age} days, which is less than the recommended 365 days."

            findings.append(report)

        return findings
