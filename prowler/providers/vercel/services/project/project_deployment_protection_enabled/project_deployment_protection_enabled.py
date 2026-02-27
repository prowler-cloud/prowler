from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client


class project_deployment_protection_enabled(Check):
    """Check if deployment protection is enabled on preview deployments.

    This class verifies whether each Vercel project has deployment protection
    configured for preview deployments to prevent unauthorized access.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Deployment Protection check.

        Iterates over all projects and checks if deployment protection is enabled
        on preview deployments.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if (
                project.deployment_protection is not None
                and project.deployment_protection.level != "none"
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has deployment protection enabled "
                    f"with level '{project.deployment_protection.level}' on preview deployments."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} does not have deployment protection "
                    f"enabled on preview deployments."
                )

            findings.append(report)

        return findings
