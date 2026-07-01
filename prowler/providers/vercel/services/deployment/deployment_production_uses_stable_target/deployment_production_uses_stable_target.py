from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.deployment.deployment_client import (
    deployment_client,
)


class deployment_production_uses_stable_target(Check):
    """Check if production deployments are sourced from a stable branch.

    This class verifies whether each Vercel production deployment originates
    from a configured stable branch rather than a feature branch. The list of
    stable branches is configurable via audit_config key ``stable_branches``
    (default: ``["main", "master"]``).
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

            stable_branches = deployment_client.audit_config.get(
                "stable_branches", ["main", "master"]
            )
            branch = deployment.git_source.get("branch") or ""
            if branch in stable_branches:
                report.status = "PASS"
                report.status_extended = (
                    f"Production deployment {deployment.name} ({deployment.id}) "
                    f"is sourced from stable branch '{branch}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Production deployment {deployment.name} ({deployment.id}) "
                    f"is sourced from branch '{branch}' instead of a "
                    f"configured stable branch ({', '.join(stable_branches)})."
                )

            findings.append(report)

        return findings
