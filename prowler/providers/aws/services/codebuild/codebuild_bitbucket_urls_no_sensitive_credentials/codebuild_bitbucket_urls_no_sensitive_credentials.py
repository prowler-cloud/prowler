import re

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_bitbucket_urls_no_sensitive_credentials(Check):
    def execute(self):
        findings = []
        token_pattern = re.compile(r"https://x-token-auth:[^@]+@bitbucket\.org/.+\.git")
        user_pass_pattern = re.compile(r"https://[^:]+:[^@]+@bitbucket\.org/.+\.git")
        for project in codebuild_client.projects.values():
            report = Check_Report_AWS(self.metadata())
            report.region = project.region
            report.resource_id = project.name
            report.resource_arn = project.arn
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not contain sensitive credentials in Bitbucket repository URLs."
            secrets_found = []

            for url in project.bitbucket_urls:
                if token_pattern.match(url):
                    secrets_found.append(f"Token in URL {url}")
                elif user_pass_pattern.match(url):
                    secrets_found.append(f"Basic Auth Credentials in URL {url}")

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has sensitive credentials in Bitbucket repository URLs: {', '.join(secrets_found)}."

            findings.append(report)

        return findings
