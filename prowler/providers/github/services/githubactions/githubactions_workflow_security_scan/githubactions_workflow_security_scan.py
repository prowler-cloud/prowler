import json
from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.githubactions.githubactions_client import (
    githubactions_client,
)
from prowler.providers.github.services.repository.repository_client import (
    repository_client,
)


class githubactions_workflow_security_scan(Check):
    def execute(self) -> List[CheckReportGithub]:
        findings = []

        if not githubactions_client.scan_enabled:
            return findings

        scan_errors = getattr(githubactions_client, "scan_errors", {})
        if not isinstance(scan_errors, dict):
            scan_errors = {}

        for repo_id, repo in repository_client.repositories.items():
            repo_findings = githubactions_client.findings.get(repo_id, [])

            if repo_id in scan_errors:
                report = CheckReportGithub(
                    metadata=self.metadata(),
                    resource=repo,
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"GitHub Actions workflow security scan for repository {repo.name} "
                    f"could not be completed: {scan_errors[repo_id]}"
                )
                findings.append(report)
            elif not repo_findings:
                report = CheckReportGithub(
                    metadata=self.metadata(),
                    resource=repo,
                )
                report.status = "PASS"
                report.status_extended = f"Repository {repo.name} has no GitHub Actions workflow security issues detected by zizmor."
                findings.append(report)
            else:
                for f in repo_findings:
                    metadata_dict = {
                        "Provider": "github",
                        "CheckID": f.finding_id,
                        "CheckTitle": f"GitHub Actions workflows free of {f.ident} issues",
                        "CheckType": [],
                        "ServiceName": "githubactions",
                        "SubServiceName": "",
                        "ResourceIdTemplate": "",
                        "Severity": f.severity,
                        "ResourceType": "GitHubActionsWorkflow",
                        "ResourceGroup": "devops",
                        "Description": f.description[:400],
                        "Risk": f.description[:400],
                        "RelatedUrl": "",
                        "Remediation": {
                            "Code": {
                                "CLI": "",
                                "NativeIaC": "",
                                "Other": "",
                                "Terraform": "",
                            },
                            "Recommendation": {
                                "Text": f"Review the zizmor documentation for {f.ident}: {f.url}",
                                "Url": "",
                            },
                        },
                        "Categories": ["software-supply-chain"],
                        "DependsOn": [],
                        "RelatedTo": [],
                        "Notes": "",
                        "AdditionalURLs": [f.url] if f.url else [],
                    }
                    report = CheckReportGithub(
                        metadata=json.dumps(metadata_dict),
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
                    findings.append(report)

        return findings
