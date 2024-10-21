from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client

class codebuild_project_artifact_encryption(Check):
    def execute(self):
        findings = []

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags

            if project.buildspec and project.artifact_encryption:
                report.status = "PASS"
                report.status_extended = f"CodeBuild project {project.name} has artifact encryption configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} does not have artifact encryption configured."

            findings.append(report)

        return findings
