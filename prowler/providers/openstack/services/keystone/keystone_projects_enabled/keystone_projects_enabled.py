from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.keystone.keystone_client import (
    keystone_client,
)


class keystone_projects_enabled(Check):
    """Ensure Keystone projects are enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for project in keystone_client.projects:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=project)
            if project.enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name or project.id} is enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {project.name or project.id} is disabled."
                )
            findings.append(report)

        return findings
