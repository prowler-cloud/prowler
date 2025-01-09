import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_source_repo_url_no_sensitive_credentials(Check):
    def execute(self):
        findings = []
        token_pattern = re.compile(r"https://x-token-auth:[^@]+@bitbucket\.org/.+\.git")
        user_pass_pattern = re.compile(r"https://[^:]+:[^@]+@bitbucket\.org/.+\.git")
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.resource_tags = project.tags
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not contain sensitive credentials in any source repository URLs."
            secrets_found = []

            if project.source and project.source.type == "BITBUCKET":
                if token_pattern.match(project.source.location):
                    secrets_found.append(
                        f"Token in {project.source.type} URL {project.source.location}"
                    )
                elif user_pass_pattern.match(project.source.location):
                    secrets_found.append(
                        f"Basic Auth Credentials in {project.source.type} URL {project.source.location}"
                    )
            for url in project.secondary_sources:
                if url.type == "BITBUCKET":
                    if token_pattern.match(url.location):
                        secrets_found.append(f"Token in {url.type} URL {url.location}")
                    elif user_pass_pattern.match(url.location):
                        secrets_found.append(
                            f"Basic Auth Credentials in {url.type} URL {url.location}"
                        )
            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has sensitive credentials in source repository URLs: {', '.join(secrets_found)}."

            findings.append(report)

        return findings
