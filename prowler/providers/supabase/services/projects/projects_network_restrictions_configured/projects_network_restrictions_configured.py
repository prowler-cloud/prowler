from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.projects.projects_client import projects_client


class projects_network_restrictions_configured(Check):
    """Check that direct database access is restricted to known IP ranges.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for project in projects_client.projects.values():
            if project.network_restrictions_entitled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=project)
            if project.allowed_cidrs_restricted:
                report.status = "PASS"
                report.status_extended = f"Project {project.name} restricts database access to {len(project.allowed_cidrs) + len(project.allowed_cidrs_v6)} allowed CIDR range(s)."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} allows direct database connections from any IP address."
            findings.append(report)
        return findings
