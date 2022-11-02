from lib.check.models import Check, Check_Report
from providers.aws.services.cloudwatch.logs_client import logs_client
from providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client


class cloudwatch_log_metric_filter_unauthorized_api_calls(Check):
    def execute(self):
        # 1. Iterate for CloudWatch Log Group in CloudTrail trails

        # 2. Describe metric filters
        # 3. Check if there is an alarm for the metric
        findings = []
        report = Check_Report(self.metadata)
        report.status = "PASS"
        report.status_extended = "CloudWatch doesn't allows cross-account sharing"
        report.resource_id = "CloudWatch-CrossAccountSharingRole"
        for filter in logs_client.metric_filters:
            if role["RoleName"] == "CloudWatch-CrossAccountSharingRole":
                report.resource_arn = role["Arn"]
                report.status = "FAIL"
                report.status_extended = "CloudWatch has allowed cross-account sharing."
        findings.append(report)
        return findings
