from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_client import (
    elasticbeanstalk_client,
)


class elasticbeanstalk_environment_enhanced_health_reporting(Check):
    def execute(self):
        findings = []
        for environment in elasticbeanstalk_client.environments.values():
            report = Check_Report_AWS(self.metadata())
            report.region = environment.region
            report.resource_id = environment.name
            report.resource_arn = environment.arn
            report.resource_tags = environment.tags
            report.status = "PASS"
            report.status_extended = f"Elastic Beanstalk environment {environment.name} has enhanced health reporting enabled."

            if environment.health_reporting != "enhanced":
                report.status = "FAIL"
                report.status_extended = f"Elastic Beanstalk environment {environment.name} does not have enhanced health reporting enabled."

            findings.append(report)

        return findings
