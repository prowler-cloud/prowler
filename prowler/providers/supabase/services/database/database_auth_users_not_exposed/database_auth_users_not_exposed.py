from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.database.database_client import (
    database_client,
)
from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabaseObject,
)

ADVISOR_LINTS = ["auth_users_exposed"]


class database_auth_users_not_exposed(Check):
    """Supabase auth.users data is not exposed through views or tables in the Data API.

    Uses the Supabase security advisor lint(s) ``auth_users_exposed``. A project passes
    when the advisor ran and reported no such lint; every reported object
    produces its own failing finding.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one PASS per clean project or one FAIL per flagged object."""
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
                report.status_extended = f"Project {database.name} does not expose auth.users through the Data API."
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
                report.status_extended = f"{lint.object_type.capitalize() or 'Object'} {lint.qualified_name} in project {database.name} exposes auth.users data to the anon or authenticated roles."
                findings.append(report)
        return findings
