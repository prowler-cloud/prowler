from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.published.published_client import (
    published_client,
)


class published_app_strict_csp_configured(Check):
    """Content-Security-Policy must define default-src and exclude unsafe-inline / unsafe-eval / wildcards."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for inspection in published_client.inspections.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=inspection)
            if not inspection.reachable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not reach published app {inspection.app_name}; "
                    "verify CSP manually."
                )
            elif "content-security-policy" not in inspection.headers:
                report.status = "FAIL"
                report.status_extended = (
                    f"Published app {inspection.app_name} does not return a "
                    "Content-Security-Policy header."
                )
            elif inspection.has_strict_csp:
                report.status = "PASS"
                report.status_extended = (
                    f"Published app {inspection.app_name} returns a strict "
                    "Content-Security-Policy."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Published app {inspection.app_name} returns a permissive "
                    "Content-Security-Policy (uses wildcard, 'unsafe-inline', "
                    "or 'unsafe-eval', or omits default-src)."
                )
            findings.append(report)
        return findings
