from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for user in iam_client.credential_report:
            if user["user"] == "<root_account>":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = user["user"]
                report.resource_arn = user["arn"]
                if user["mfa_active"] == "false":
                    report.status = "FAIL"
                    report.status_extended = "MFA is not enabled for root account."
                else:
                    report.status = "PASS"
                    report.status_extended = "MFA is enabled for root account."
                findings.append(report)

        return findings
