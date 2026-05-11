from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_workspace_visibility_for_internal_apps(Check):
    """Internal Lovable apps must use workspace visibility, not public.

    Lovable best practice: apps that aren't intended for public use should be
    set to "workspace" visibility so authentication is required and external
    visitors cannot reach them.
    """

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            is_internal = bool(app.tags) and (
                app.tags.get("environment") in {"internal", "staging", "dev"}
                or app.tags.get("internal") is True
            )

            if not is_internal and not app.is_published:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) is not published; visibility "
                    "controls are not applicable yet."
                )
            elif app.visibility == "workspace":
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) is restricted to workspace "
                    "visibility."
                )
            elif app.visibility == "public":
                if is_internal:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"App {app.name} ({app.id}) is tagged internal but "
                        "is published with public visibility."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"App {app.name} ({app.id}) is intentionally public; "
                        "ensure auth is enforced server-side."
                    )
            else:
                report.status = "MANUAL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) visibility is "
                    f"'{app.visibility}'. Review in the Lovable dashboard."
                )

            findings.append(report)
        return findings
