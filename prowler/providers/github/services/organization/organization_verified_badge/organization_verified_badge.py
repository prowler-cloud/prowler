from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_verified_badge(Check):
    """Check if GitHub organizations are verified."""

    def execute(self) -> List[CheckReportGithub]:
        findings: List[CheckReportGithub] = []

        for org in organization_client.organizations.values():
            report = CheckReportGithub(metadata=self.metadata(), resource=org)

            if org.is_verified:
                report.status = "PASS"
                report.status_extended = (
                    f"Organization {org.name} is verified on GitHub."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {org.name} is not verified on GitHub."
                )

            findings.append(report)

        return findings
