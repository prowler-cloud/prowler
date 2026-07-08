from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.project.project_client import project_client


class project_auto_expose_system_env_disabled(Check):
    """Check if automatic exposure of system environment variables is disabled.

    This class verifies whether each Vercel project has the automatic exposure
    of system environment variables disabled to prevent information leakage.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Auto Expose System Env check.

        Iterates over all projects and checks if automatic exposure of system
        environment variables is disabled.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if not project.auto_expose_system_envs:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} does not automatically expose "
                    f"system environment variables to the build process."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} automatically exposes system "
                    f"environment variables to the build process."
                )

            findings.append(report)

        return findings
