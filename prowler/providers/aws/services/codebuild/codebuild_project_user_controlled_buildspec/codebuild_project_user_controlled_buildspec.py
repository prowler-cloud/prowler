from re import search

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_user_controlled_buildspec(Check):
    def execute(self):
        findings = []
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not use an user controlled buildspec."
            if project.buildspec:
                if search(r".*\.yaml$", project.buildspec) or search(
                    r".*\.yml$", project.buildspec
                ):
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} uses an user controlled buildspec."

            findings.append(report)

        return findings
