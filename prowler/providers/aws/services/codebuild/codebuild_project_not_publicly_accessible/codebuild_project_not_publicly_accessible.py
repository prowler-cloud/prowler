from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_not_publicly_accessible(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        projects = codebuild_client.projects
        for arn, project in projects.items():
            report = Check_Report_AWS(self.metadata(), resource=project)
            report.resource_id = project.name
            report.resource_arn = arn
            report.region = project.region
            report.status = "FAIL"
            report.status_extended = f"CodeBuild project {project.name} is public."

            if project.project_visibility == "PRIVATE":
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} is private."

            findings.append(report)

        return findings
