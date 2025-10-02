from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_base_permissions_strict(Check):
    """Check if organization base permissions are set to strict values.

    This class verifies whether each organization has base repository permissions set to
    the lowest privilege level ("read" or "none") to minimize security risks.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Base Permissions Strict check.

        Iterates over all organizations and checks if base permissions are set to "read" or "none".

        Returns:
            List[CheckReportGithub]: A list of reports for each organization
        """
        findings = []
        strict_permissions = ["read", "none"]

        for org in organization_client.organizations.values():
            if org.base_permissions is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {org.name} has base repository permission set to "
                    f"'{org.base_permissions}' which is not strict (should be 'read' or 'none')."
                )

                if org.base_permissions.lower() in strict_permissions:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Organization {org.name} has strict base repository permission "
                        f"set to '{org.base_permissions}'."
                    )

                findings.append(report)

        return findings
