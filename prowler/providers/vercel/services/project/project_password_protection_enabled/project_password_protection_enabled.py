from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.lib.billing import plan_reason_suffix
from prowler.providers.vercel.services.project.project_client import project_client


class project_password_protection_enabled(Check):
    """Check if password protection is enabled for the project.

    This class verifies whether each Vercel project has password protection
    configured to restrict access to deployments with a shared password.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Password Protection check.

        Iterates over all projects and checks if password protection is configured.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if (
                project.password_protection
                and isinstance(project.password_protection, dict)
                and project.password_protection.get("deploymentType")
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has password protection configured "
                    f"to restrict access to deployments."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name} does not have password protection "
                    f"configured for deployments."
                    f"{plan_reason_suffix(project.billing_plan, {'hobby'}, 'password protection is not available on the Vercel Hobby plan.')}"
                )

            findings.append(report)

        return findings
