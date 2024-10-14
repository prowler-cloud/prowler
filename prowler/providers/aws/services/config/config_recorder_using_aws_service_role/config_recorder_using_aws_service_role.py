from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.config.config_client import config_client


class config_recorder_using_aws_service_role(Check):
    def execute(self):
        findings = []
        for recorder in config_client.recorders.values():
            if recorder.name and recorder.recording:
                report = Check_Report_AWS(self.metadata())
                report.region = recorder.region
                report.resource_arn = config_client._get_recorder_arn_template(
                    recorder.region
                )
                report.resource_id = recorder.name
                if (
                    recorder.role_arn
                    == f"arn:{config_client.audited_partition}:iam::{config_client.audited_account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
                ):
                    report.status = "PASS"
                    report.status_extended = f"AWS Config recorder {recorder.name} is using AWSServiceRoleForConfig."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"AWS Config recorder {recorder.name} is not using AWSServiceRoleForConfig."

                findings.append(report)

        return findings
