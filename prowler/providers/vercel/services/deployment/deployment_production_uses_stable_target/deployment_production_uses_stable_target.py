from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.deployment.deployment_client import (
    deployment_client,
)


class deployment_production_uses_stable_target(Check):
    """Check if production deployments are sourced from a stable branch.

    This class verifies whether each Vercel production deployment originates
    from a stable branch (main or master) rather than a feature branch.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Production Deployment Stable Target check.

        Iterates over all deployments, filters for production targets with
        git source information, and checks if the branch is main or master.

        Returns:
            List[CheckReportVercel]: A list of reports for each production deployment.
        """
        findings = []
        for deployment in deployment_client.deployments.values():
            if deployment.target != "production":
                continue

            if not deployment.git_source:
                continue

            report = CheckReportVercel(metadata=self.metadata(), resource=deployment)

            branch = deployment.git_source.get("branch", "")
            if branch in ("main", "master"):
                report.status = "PASS"
                report.status_extended = (
                    f"Production deployment {deployment.name} ({deployment.id}) "
                    f"is sourced from stable branch '{branch}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Production deployment {deployment.name} ({deployment.id}) "
                    f"is sourced from feature branch '{branch}' instead of main or master."
                )

            findings.append(report)

        return findings
