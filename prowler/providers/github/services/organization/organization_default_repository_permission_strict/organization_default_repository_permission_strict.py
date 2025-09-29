from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_default_repository_permission_strict(Check):
    """Check if an organization's base repository permission is set to a strict level.

    PASS: base permission is "read" or "none"
    FAIL: base permission is "write" or "admin" (or any other non-strict value)
    """

    def execute(self) -> List[CheckReportGithub]:
        findings = []
        for org in organization_client.organizations.values():
            base_perm = getattr(org, "base_permission", None)
            if base_perm is None:
                # Unknown / no permission to read → skip producing a finding
                continue

            p = str(base_perm).lower()
            report = CheckReportGithub(metadata=self.metadata(), resource=org)

            if p in ("read", "none"):
                report.status = "PASS"
                report.status_extended = f"Organization {org.name} base repository permission is '{p}', which is strict."
            else:
                report.status = "FAIL"
                report.status_extended = f"Organization {org.name} base repository permission is '{p}', which is not strict."

            findings.append(report)

        return findings
