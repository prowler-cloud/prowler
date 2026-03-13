from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_password_policy_password_reuse_prevention(Check):
    """Check if RAM password policy prevents password reuse."""

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

            if ram_client.password_policy.password_reuse_prevention >= 5:
                report.status = "PASS"
                report.status_extended = f"RAM password policy prevents password reuse (history: {ram_client.password_policy.password_reuse_prevention} passwords)."
            else:
                report.status = "FAIL"
                if ram_client.password_policy.password_reuse_prevention == 0:
                    report.status_extended = (
                        "RAM password policy does not prevent password reuse."
                    )
                else:
                    report.status_extended = f"RAM password policy prevents reuse of only {ram_client.password_policy.password_reuse_prevention} previous passwords, which is less than the recommended 5."

            findings.append(report)

        return findings
