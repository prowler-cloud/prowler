from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_minimum_length(Check):
    """Check if RAM password policy requires minimum length of 14 or greater."""

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

            if ram_client.password_policy.minimum_password_length >= 14:
                report.status = "PASS"
                report.status_extended = f"RAM password policy requires minimum length of {ram_client.password_policy.minimum_password_length} characters."
            else:
                report.status = "FAIL"
                report.status_extended = f"RAM password policy requires minimum length of {ram_client.password_policy.minimum_password_length} characters, which is less than the recommended 14 characters."

            findings.append(report)

        return findings
