from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_supabase_edge_functions_authenticated(Check):
    """Every Supabase Edge Function backing a Lovable app must enforce auth."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            if not app.has_supabase_backing or not app.edge_functions:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has no Edge Functions to check."
                )
                findings.append(report)
                continue

            unauth = [
                fn
                for fn in app.edge_functions
                if fn not in app.edge_functions_with_auth
            ]
            if unauth:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has Edge Function(s) without "
                    f"authentication enforcement: {', '.join(unauth)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has authentication enforced on "
                    f"all {len(app.edge_functions)} Edge Function(s)."
                )
            findings.append(report)
        return findings
