import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.config.config_client import config_client


class config_recorder_using_aws_service_role(Check):
    def execute(self):
        service_role_arn_pattern = re.compile(
            r"arn:.*:iam::\d{12}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        )
        findings = []
        for recorder in config_client.recorders.values():
            if recorder.name and recorder.recording:
                report = Check_Report_AWS(self.metadata())
                report.region = recorder.region
                report.resource_arn = config_client._get_recorder_arn_template(
                    recorder.region
                )
                report.resource_id = recorder.name
                # Check if Config recorder is using AWS service role
                if service_role_arn_pattern.match(recorder.role_arn):
                    report.status = "PASS"
                    report.status_extended = f"AWS Config recorder {recorder.name} is using AWSServiceRoleForConfig."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"AWS Config recorder {recorder.name} is not using AWSServiceRoleForConfig."

                if report.status == "FAIL" and (
                    config_client.audit_config.get("mute_non_default_regions", False)
                    and not recorder.region == config_client.region
                ):
                    report.muted = True

                findings.append(report)

        return findings
