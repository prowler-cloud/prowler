from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)


class elasticbeanstalk_environment_cloudwatch_logging_enabled(Check):
    def execute(self):
        findings = []
        for environment in elasticbeanstalk_client.environments.values():
            report = Check_Report_AWS(self.metadata())
            report.region = environment.region
            report.resource_id = environment.name
            report.resource_arn = environment.arn
            report.resource_tags = environment.tags
            report.status = "PASS"
            report.status_extended = f"Elastic Beanstalk environment {environment.name} is sending logs to CloudWatch Logs."

            if environment.cloudwatch_stream_logs != "true":
                report.status = "FAIL"
                report.status_extended = f"Elastic Beanstalk environment {environment.name} is not sending logs to CloudWatch Logs."

            findings.append(report)

        return findings
