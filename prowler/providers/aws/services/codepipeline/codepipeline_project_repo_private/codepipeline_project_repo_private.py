import ssl
import urllib.error
import urllib.request

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codepipeline.codepipeline_client import (
    codepipeline_client,
)


class codepipeline_project_repo_private(Check):
    """Check if CodePipeline source repositories are private."""

    def execute(self):
        findings = []

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

                # Try both GitHub and GitLab URLs
                github_url = f"https://github.com/{repo_id}"
                gitlab_url = f"https://gitlab.com/{repo_id}"

                is_public_github = self._is_public_repo(github_url)
                is_public_gitlab = self._is_public_repo(gitlab_url)

                if is_public_github:
                    report.status = "FAIL"
                    report.status_extended = f"CodePipeline {pipeline.name} source repository is public: {github_url}"
                elif is_public_gitlab:
                    report.status = "FAIL"
                    report.status_extended = f"CodePipeline {pipeline.name} source repository is public: {gitlab_url}"
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"CodePipeline {pipeline.name} source repository is private"
                    )

                findings.append(report)

        return findings

    def _is_public_repo(self, repo_url: str) -> bool:
        """Check if a repository is public by attempting to access it anonymously."""
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        try:
            context = ssl._create_unverified_context()
            req = urllib.request.Request(repo_url, method="HEAD")
            response = urllib.request.urlopen(req, context=context)
            return not response.geturl().endswith("sign_in")
        except (urllib.error.HTTPError, urllib.error.URLError):
            return False
