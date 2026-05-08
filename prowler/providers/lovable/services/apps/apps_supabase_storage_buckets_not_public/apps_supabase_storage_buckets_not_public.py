from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_supabase_storage_buckets_not_public(Check):
    """User-content Supabase storage buckets must not be marked public."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            if not app.has_supabase_backing:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has no Supabase storage to check."
                )
                findings.append(report)
                continue

            if app.storage_buckets_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has public Supabase storage "
                    f"bucket(s): {', '.join(app.storage_buckets_public)}. "
                    "Confirm these intentionally serve only public assets and "
                    "no user uploads."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has no public Supabase "
                    "storage buckets."
                )
            findings.append(report)
        return findings
