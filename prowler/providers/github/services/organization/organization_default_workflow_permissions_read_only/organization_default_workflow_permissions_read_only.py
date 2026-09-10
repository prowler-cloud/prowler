from typing import List

from prowler.lib.check.models import Check, CheckReportGithub
from prowler.providers.github.services.organization.organization_client import (
    organization_client,
)


class organization_default_workflow_permissions_read_only(Check):
    """Check if the default GITHUB_TOKEN permissions granted to workflows are read-only.

    This class verifies whether each organization grants workflows a read-only GITHUB_TOKEN
    by default, instead of a token with write access to the repository contents.
    """

    def execute(self) -> List[CheckReportGithub]:
        """Execute the Github Organization Default Workflow Permissions Read Only check.

        Iterates over all organizations and checks the default GITHUB_TOKEN permissions
        granted to GitHub Actions workflows.

        Returns:
            List[CheckReportGithub]: A list of reports for each organization
        """
        findings = []
        for org in organization_client.organizations.values():
            if org.default_workflow_permissions is not None:
                report = CheckReportGithub(metadata=self.metadata(), resource=org)
                report.status = "FAIL"
                report.status_extended = f"Organization {org.name} grants workflows a default GITHUB_TOKEN with {org.default_workflow_permissions} permissions."

                if org.default_workflow_permissions == "read":
                    report.status = "PASS"
                    report.status_extended = f"Organization {org.name} grants workflows a read-only default GITHUB_TOKEN."

                findings.append(report)

        return findings
