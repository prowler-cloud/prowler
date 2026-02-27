from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.deployment.deployment_client import (
    deployment_client,
)


class deployment_preview_not_publicly_accessible(Check):
    """Check if preview deployments have deployment protection configured.

    This class verifies whether each Vercel preview deployment has deployment
    protection enabled to prevent unauthorized public access to preview URLs.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Preview Deployment Protection check.

        Iterates over all deployments, filters for preview targets, and checks
        if deployment protection is configured.

        Returns:
            List[CheckReportVercel]: A list of reports for each preview deployment.
        """
        findings = []
        for deployment in deployment_client.deployments.values():
            if deployment.target != "preview":
                continue

            report = CheckReportVercel(metadata=self.metadata(), resource=deployment)

            if deployment.deployment_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"Preview deployment {deployment.name} ({deployment.id}) "
                    f"has deployment protection configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Preview deployment {deployment.name} ({deployment.id}) "
                    f"does not have deployment protection configured and is publicly accessible."
                )

            findings.append(report)

        return findings
