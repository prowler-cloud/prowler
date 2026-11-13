from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.database.database_client import (
    database_client,
)
from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabaseObject,
)

ADVISOR_LINTS = ["function_search_path_mutable"]


class database_functions_search_path_set(Check):
    """Supabase database functions pin their search_path.

    Uses the Supabase security advisor lint(s) ``function_search_path_mutable``. A project passes
    when the advisor ran and reported no such lint; every reported function
    produces its own failing finding.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one PASS per clean project or one FAIL per flagged function."""
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
                report.status_extended = f"Project {database.name} has no function with a mutable search_path."
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
                report.status_extended = f"Function {lint.qualified_name} in project {database.name} has a mutable search_path and can be hijacked through schema shadowing."
                findings.append(report)
        return findings
