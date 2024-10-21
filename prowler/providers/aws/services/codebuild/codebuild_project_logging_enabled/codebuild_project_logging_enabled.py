from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client

class codebuild_project_logging_enabled(Check):
    def execute(self):
        findings = []

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags

            if project.logging_enabled:
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} has logging enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} does not have logging enabled."

            findings.append(report)

        return findings
