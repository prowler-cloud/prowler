from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.projects.projects_client import projects_client


class projects_pitr_enabled(Check):
    """Check that Point-in-Time Recovery is enabled for the project database.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for project in projects_client.projects.values():
            if project.pitr_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=project)
            if project.pitr_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {project.name} has Point-in-Time Recovery enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} does not have Point-in-Time Recovery enabled and relies on daily backups only."
            findings.append(report)
        return findings
