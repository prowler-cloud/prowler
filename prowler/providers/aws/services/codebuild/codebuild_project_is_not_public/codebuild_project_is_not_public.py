from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS

from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_is_not_public(Check):  # type: ignore[misc]
    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        projects = codebuild_client.projects
        for arn, project in projects.items():
            report = Check_Report_AWS(self.metadata(), resource=project)
            report.resource_id = project.name
            report.resource_arn = arn
            report.region = project.region

            if project.project_visibility == "PUBLIC_READ":
                report.status = "FAILED"
                report.status_extended = f"CodeBuild project {project.name} is PUBLIC."
            elif project.project_visibility == "PRIVATE":
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} is PRIVATE."
            else:
                report.status = "UNKNOWN"
                report.status_extended = f"CodeBuild project {project.name} has an unknown visibility."

            findings.append(report)

        return findings
