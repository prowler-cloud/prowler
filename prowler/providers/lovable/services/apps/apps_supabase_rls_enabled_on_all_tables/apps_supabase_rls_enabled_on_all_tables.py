from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_supabase_rls_enabled_on_all_tables(Check):
    """RLS must be enabled on every table in the Supabase backing the app."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            if not app.has_supabase_backing:
                report.status = "MANUAL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) does not have a known Supabase "
                    "backend; verify data-access posture manually."
                )
            elif app.rls_enabled_on_all_tables and not app.tables_without_rls:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has Row Level Security enabled "
                    "on every Supabase table."
                )
            else:
                without_rls = ", ".join(app.tables_without_rls) or "unspecified"
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has Supabase tables without RLS "
                    f"policies: {without_rls}."
                )
            findings.append(report)
        return findings
