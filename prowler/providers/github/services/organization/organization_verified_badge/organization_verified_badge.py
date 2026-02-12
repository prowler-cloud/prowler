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

            is_verified = getattr(org, "is_verified", None)

            # Treat None as False (edge case)
            if is_verified is None:
                is_verified = False

            if is_verified is False:
                raw = getattr(org, "raw_data", None)
                if isinstance(raw, dict):
                    is_verified = bool(raw.get("is_verified", False))

            if is_verified:
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
