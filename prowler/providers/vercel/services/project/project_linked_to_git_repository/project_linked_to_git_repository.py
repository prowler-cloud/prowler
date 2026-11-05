from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client


class project_linked_to_git_repository(Check):
    """Check that the project is linked to a Git repository.

    This class verifies whether each Vercel project is connected to a Git
    repository. A linked project still accepts CLI or REST API deployments, so
    a PASS does not prove every deployment came from a reviewed commit.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Git repository link check.

        Iterates over all projects and checks if a Git repository is linked.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            link = project.git_repository or {}
            repo = link.get("repo") or link.get("repoId")
            if repo:
                provider = link.get("type", "git")
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} is linked to the {provider} "
                    f"repository {repo}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} is not linked to a Git repository, "
                    f"so deployments can be pushed from any workstation without "
                    f"code review or commit history."
                )

            findings.append(report)

        return findings
