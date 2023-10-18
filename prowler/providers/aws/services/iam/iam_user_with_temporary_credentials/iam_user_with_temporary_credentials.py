from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_with_temporary_credentials(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for last_accessed_services in iam_client.user_temporary_credentials_usage:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = last_accessed_services["user"].name
            report.resource_arn = last_accessed_services["user"].arn
            report.region = iam_client.region
            report.status = "FAIL"
            report.status_extended = f"User {last_accessed_services['user'].name} has long lived credentials with access to other services than IAM or STS."
            if last_accessed_services["temporary_credentials_usage"]:
                report.status = "PASS"
                report.status_extended = f"User {last_accessed_services['user'].name} doesn't have long lived credentials with access to other services than IAM or STS."

            findings.append(report)

        return findings
