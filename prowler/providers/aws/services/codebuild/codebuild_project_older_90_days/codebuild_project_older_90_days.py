from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_older_90_days(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects:
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = ""
            report.status = "PASS"
            report.status_extended = (
                f"CodeBuild project {project.name} has been invoked in the last 90 days"
            )
            if project.last_invoked_time:
                if (datetime.now(timezone.utc) - project.last_invoked_time).days > 90:
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} has not been invoked in the last 90 days"
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"CodeBuild project {project.name} has never been built"
                )

            findings.append(report)

        return findings
