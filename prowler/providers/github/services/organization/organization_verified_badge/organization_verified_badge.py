from typing import List

from prowler.lib.check.models import Check, CheckReportGithub


class organization_verified_badge(Check):
    """Check if GitHub organizations are verified."""

    def execute(self) -> List[CheckReportGithub]:
        from prowler.providers.github.services.organization.organization_client import (
            organization_client,
        )

        findings = []

        for org in organization_client.organizations.values():
            report = CheckReportGithub(metadata=self.metadata(), resource=org)

            is_verified = False
            if hasattr(org, "raw_data") and isinstance(org.raw_data, dict):
                is_verified = org.raw_data.get("is_verified", False)

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
