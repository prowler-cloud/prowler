from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client


class project_directory_listing_disabled(Check):
    """Check if directory listing is disabled for the project.

    This class verifies whether each Vercel project has directory listing
    disabled to prevent exposure of the project's file structure.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Directory Listing check.

        Iterates over all projects and checks if directory listing is disabled.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if not project.directory_listing:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has directory listing disabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} has directory listing enabled, "
                    f"which may expose the project's file structure to visitors."
                )

            findings.append(report)

        return findings
