from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.database.database_client import (
    database_client,
)
from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabaseObject,
)

ADVISOR_LINTS = ["vulnerable_postgres_version"]


class database_postgres_version_not_vulnerable(Check):
    """Supabase project runs a Postgres version without known security vulnerabilities.

    Uses the Supabase security advisor lint(s) ``vulnerable_postgres_version``. A project passes
    when the advisor ran and reported no such lint; every reported project
    produces its own failing finding.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one PASS per clean project or one FAIL per flagged project."""
        findings = []
        for database in database_client.databases.values():
            if not database.advisor_available:
                continue
            lints = database.lints_named(*ADVISOR_LINTS)
            if not lints:
                report = CheckReportSupabase(
                    metadata=self.metadata(), resource=database
                )
                report.status = "PASS"
                report.status_extended = f"Project {database.name} runs a Postgres version without known security vulnerabilities."
                findings.append(report)
                continue
            for lint in lints:
                resource = SupabaseDatabaseObject(
                    **database.model_dump(exclude={"lints", "advisor_available"}),
                    lint=lint,
                )
                report = CheckReportSupabase(
                    metadata=self.metadata(), resource=resource
                )
                report.status = "FAIL"
                report.status_extended = f"Project {database.name} runs a Postgres version with known security vulnerabilities and should be upgraded."
                findings.append(report)
        return findings
