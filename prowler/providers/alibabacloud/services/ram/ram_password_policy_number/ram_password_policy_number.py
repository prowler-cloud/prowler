from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_number(Check):
    """Check if RAM password policy requires at least one number."""

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

            if ram_client.password_policy.require_numbers:
                report.status = "PASS"
                report.status_extended = (
                    "RAM password policy requires at least one number."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "RAM password policy does not require at least one number."
                )

            findings.append(report)

        return findings
