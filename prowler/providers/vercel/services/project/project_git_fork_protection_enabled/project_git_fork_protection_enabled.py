from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client


class project_git_fork_protection_enabled(Check):
    """Check if Git fork protection is enabled for the project.

    This class verifies whether each Vercel project has Git fork protection
    enabled to prevent untrusted forks from accessing environment variables
    and triggering deployments.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Git Fork Protection check.

        Iterates over all projects and checks if Git fork protection is enabled.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if project.git_fork_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has Git fork protection enabled, "
                    f"preventing untrusted forks from accessing secrets."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} does not have Git fork protection "
                    f"enabled, allowing forks to access environment variables "
                    f"and trigger deployments."
                )

            findings.append(report)

        return findings
