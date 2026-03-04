from typing import List

from prowler.lib.check.models import Check, CheckReportGithub, Severity
from prowler.providers.github.services.githubactions.githubactions_client import (
    githubactions_client,
)
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class githubactions_workflow_security_scan(Check):
    def execute(self) -> List[CheckReportGithub]:
        findings = []

        for repo_id, repo in repository_client.repositories.items():
            repo_findings = githubactions_client.findings.get(repo_id, [])

            if not repo_findings:
                report = CheckReportGithub(
                    metadata=self.metadata(),
                    resource=repo,
                )
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} has no GitHub Actions workflow security issues detected by zizmor."
                findings.append(report)
            else:
                for f in repo_findings:
                    report = CheckReportGithub(
                        metadata=self.metadata(),
                        resource=repo,
                        resource_name=f.workflow_file,
                        resource_id=str(f.repo_id),
                        owner=f.repo_owner,
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"GitHub Actions security issue in {f.workflow_file} at {f.line_range}: "
                        f"{f.description}. "
                        f"Confidence: {f.confidence}. "
                        f"Details: {f.annotation}. "
                        f"URL: {f.workflow_url}"
                    )
                    report.check_metadata.Severity = Severity(f.severity)
                    report.check_metadata.Risk = f.description
                    if f.url not in report.check_metadata.AdditionalURLs:
                        report.check_metadata.AdditionalURLs.append(f.url)
                    findings.append(report)

        return findings
