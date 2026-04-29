from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.lib.billing import plan_reason_suffix
from prowler.providers.vercel.services.project.project_client import project_client


class project_skew_protection_enabled(Check):
    """Check if skew protection is enabled for the project.

    This class verifies whether each Vercel project has skew protection enabled
    to ensure clients are served consistent deployment versions during rollouts.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Skew Protection check.

        Iterates over all projects and checks if skew protection is enabled.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if project.skew_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has skew protection enabled, "
                    f"ensuring consistent deployment versions during rollouts."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} does not have skew protection enabled, "
                    f"which may cause version mismatches during deployments."
                    f"{plan_reason_suffix(project.billing_plan, {'hobby'}, 'skew protection is not available on the Vercel Hobby plan.')}"
                )

            findings.append(report)

        return findings
