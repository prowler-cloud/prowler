import re
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_source_repo_url_check(Check):
    def execute(self):
        findings = []

        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags

            if project.source_repo_url:
                if self.is_valid_bitbucket_repo_url(project.source_repo_url):
                    report.status = "PASS"
                    report.status_extended = f"CodeBuild project {project.name} has a valid source repository URL."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"CodeBuild project {project.name} has an invalid or insecure source repository URL."
            else:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} does not have a source repository URL configured."

            findings.append(report)

        return findings

    def is_valid_bitbucket_repo_url(self, url):
        regex = re.compile(
            r"^(?:http|https)://"
            r"(?:[^@/\n]+@)?"
            r"bitbucket\.org"
            r"(?:\:[0-9]{1,5})?"
            r"(?:[/?#][^\s]*)?"
            r"$",
            re.IGNORECASE,
        )

        return bool(re.match(regex, url))
