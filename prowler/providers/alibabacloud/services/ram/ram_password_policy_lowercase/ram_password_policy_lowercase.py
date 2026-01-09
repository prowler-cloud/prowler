from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_lowercase(Check):
    """Check if RAM password policy requires at least one lowercase letter."""

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

            if ram_client.password_policy.require_lowercase_characters:
                report.status = "PASS"
                report.status_extended = (
                    "RAM password policy requires at least one lowercase letter."
                )
            else:
                report.status = "FAIL"
                report.status_extended = "RAM password policy does not require at least one lowercase letter."

            findings.append(report)

        return findings
