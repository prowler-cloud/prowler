from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.lib.billing import (
    plan_reason_suffix,
    resolve_scope_billing_plan,
)
from prowler.providers.vercel.services.project.project_client import project_client


class project_production_deployment_protection_enabled(Check):
    """Check if deployment protection is enabled on production deployments.

    This class verifies whether each Vercel project has deployment protection
    configured for production deployments to prevent unauthorized public access.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Project Production Deployment Protection check.

        Iterates over all projects and checks if deployment protection is enabled
        on production deployments.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for project in project_client.projects.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=project)

            if (
                project.production_deployment_protection is not None
                and project.production_deployment_protection.level != "none"
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has production deployment protection "
                    f"enabled with level '{project.production_deployment_protection.level}'."
                )
            else:
                report.status = "FAIL"
                billing_plan = resolve_scope_billing_plan(project.team_id)
                report.status_extended = (
                    f"Project {project.name} does not have deployment protection "
                    f"enabled on production deployments."
                    f"{plan_reason_suffix(billing_plan, {'hobby'}, 'protecting production deployments is not available on the Vercel Hobby plan.')}"
                )

            findings.append(report)

        return findings
