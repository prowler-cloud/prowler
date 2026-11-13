from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.projects.projects_client import projects_client


class projects_ssl_enforcement_enabled(Check):
    """Check that SSL is enforced for direct Postgres connections of each project.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for project in projects_client.projects.values():
            if project.ssl_enforced is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=project)
            if project.ssl_enforced:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} enforces SSL on database connections."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} does not enforce SSL, so database clients can connect in plaintext."
            findings.append(report)
        return findings
