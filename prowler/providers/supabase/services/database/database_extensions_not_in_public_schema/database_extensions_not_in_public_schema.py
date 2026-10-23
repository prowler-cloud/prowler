from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.database.database_client import (
    database_client,
)
from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabaseObject,
)

ADVISOR_LINTS = ["extension_in_public"]


class database_extensions_not_in_public_schema(Check):
    """Supabase database extensions are not installed in the public schema.

    Uses the Supabase security advisor lint(s) ``extension_in_public``. A project passes
    when the advisor ran and reported no such lint; every reported extension
    produces its own failing finding.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one PASS per clean project or one FAIL per flagged extension."""
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
                report.status_extended = f"Project {database.name} has no extension installed in the public schema."
                findings.append(report)
                continue
            for lint in lints:
                resource = SupabaseDatabaseObject(
                    **database.model_dump(exclude={"lints", "advisor_available"}),
                    lint=lint,
                )
                if lint.qualified_name:
                    resource.id = f"{database.project_ref}:{lint.qualified_name}"
                    resource.name = lint.qualified_name
                report = CheckReportSupabase(
                    metadata=self.metadata(), resource=resource
                )
                report.status = "FAIL"
                report.status_extended = f"Extension {lint.qualified_name} in project {database.name} is installed in the public schema and its functions are exposed through the Data API."
                findings.append(report)
        return findings
