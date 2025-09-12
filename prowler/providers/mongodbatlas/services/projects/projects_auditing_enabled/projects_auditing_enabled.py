from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.projects.projects_client import (
    projects_client,
)


class projects_auditing_enabled(Check):
    """Check if database auditing is enabled for MongoDB Atlas projects

    This class verifies that MongoDB Atlas projects have database auditing
    enabled to track database operations and security events.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas project auditing enabled check

        Iterates over all projects and checks if they have database auditing
        enabled by examining the audit configuration.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each project
        """
        findings = []

        for project in projects_client.projects.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=project)

            if not project.audit_config:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} does not have audit configuration available."
            else:
                # Check if audit configuration is enabled
                if project.audit_config.enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Project {project.name} has database auditing enabled."
                    )
                    if project.audit_config.audit_filter:
                        report.status_extended += f" Audit filter configured: {project.audit_config.audit_filter}"
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Project {project.name} does not have database auditing enabled."

            findings.append(report)

        return findings
