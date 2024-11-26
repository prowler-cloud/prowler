import ssl
import urllib.error
import urllib.request

import boto3

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codepipeline.codepipeline_client import (
    codepipeline_client,
)


class codepipeline_project_repo_private(Check):
    def execute(self):
        findings = []
        client = boto3.client("codestar-connections")

        for pipeline in codepipeline_client.pipelines.values():
            if (
                pipeline.source
                and pipeline.source.type == "CodeStarSourceConnection"
                and "FullRepositoryId" in str(pipeline.source.configuration)
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = pipeline.region
                report.resource_id = pipeline.name
                report.resource_arn = pipeline.arn
                report.resource_tags = pipeline.tags

                repo_id = pipeline.source.configuration.get("FullRepositoryId", "")
                connection_arn = pipeline.source.configuration.get("ConnectionArn", "")

                # Get connection details to determine provider type
                connection = client.get_connection(ConnectionArn=connection_arn)
                provider_type = connection["Connection"]["ProviderType"]

                if provider_type == "GitLab":
                    repo_url = f"https://gitlab.com/{repo_id}"
                else:
                    repo_url = f"https://github.com/{repo_id}"

                report.status = "FAIL"
                report.status_extended = f"CodePipeline {pipeline.name} source repository is public: {repo_url}"

                if not self._is_public_repo(repo_url):
                    report.status = "PASS"
                    report.status_extended = f"CodePipeline {pipeline.name} source repository is private: {repo_url}"

                findings.append(report)

        return findings

    def _is_public_repo(self, repo_url: str) -> bool:
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        try:
            context = ssl._create_unverified_context()
            req = urllib.request.Request(repo_url, method="HEAD")
            response = urllib.request.urlopen(req, context=context)

            if response.geturl().endswith("sign_in"):
                return False
            return True

        except (urllib.error.HTTPError, urllib.error.URLError):
            return False
