from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.database.database_client import (
    database_client,
)
from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabaseObject,
)

ADVISOR_LINTS = ["policy_exists_rls_disabled"]


class database_rls_enabled_on_tables_with_policies(Check):
    """Supabase tables that define policies have Row Level Security enabled.

    Uses the Supabase security advisor lint(s) ``policy_exists_rls_disabled``. A project passes
    when the advisor ran and reported no such lint; every reported table
    produces its own failing finding.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one PASS per clean project or one FAIL per flagged table."""
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
                report.status_extended = f"Project {database.name} has no table with policies defined while Row Level Security is disabled."
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
                report.status_extended = f"Table {lint.qualified_name} in project {database.name} defines policies but Row Level Security is disabled, so they are never applied."
                findings.append(report)
        return findings
