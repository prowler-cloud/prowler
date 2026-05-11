from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.published.published_client import (
    published_client,
)


class published_app_uses_https(Check):
    """The published Lovable app must be served over HTTPS."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for inspection in published_client.inspections.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=inspection)
            if not inspection.reachable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not reach published app {inspection.app_name} at "
                    f"{inspection.published_url}; verify HTTPS posture manually."
                )
            elif inspection.is_https:
                report.status = "PASS"
                report.status_extended = (
                    f"Published app {inspection.app_name} is served over HTTPS."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Published app {inspection.app_name} is reachable over "
                    f"plain HTTP at {inspection.published_url}."
                )
            findings.append(report)
        return findings
