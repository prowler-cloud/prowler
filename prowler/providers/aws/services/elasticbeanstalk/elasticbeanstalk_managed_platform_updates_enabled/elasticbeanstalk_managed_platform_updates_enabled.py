from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)


class elasticbeanstalk_managed_platform_updates_enabled(Check):
    def execute(self):
        findings = []
        for environment in elasticbeanstalk_client.environments.values():
            report = Check_Report_AWS(self.metadata())
            report.region = environment.region
            report.resource_id = environment.name
            report.resource_arn = environment.arn
            report.resource_tags = environment.tags
            report.status = "PASS"
            report.status_extended = f"Elastic Beanstalk environment {environment.name} has automated managed platform updates enabled."

            if environment.managed_platform_updates != "true":
                report.status = "FAIL"
                report.status_extended = f"Elastic Beanstalk environment {environment.name} does not have automated managed platform updates enabled."

            findings.append(report)

        return findings
