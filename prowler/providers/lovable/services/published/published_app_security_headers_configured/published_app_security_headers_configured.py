from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.published.published_client import (
    published_client,
)


class published_app_security_headers_configured(Check):
    """All required HTTP security headers must be set on the published app."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for inspection in published_client.inspections.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=inspection)
            if not inspection.reachable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not reach published app {inspection.app_name}; "
                    "verify security headers manually."
                )
            elif inspection.missing_security_headers:
                report.status = "FAIL"
                report.status_extended = (
                    f"Published app {inspection.app_name} is missing required "
                    f"security headers: {', '.join(inspection.missing_security_headers)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Published app {inspection.app_name} returns the required "
                    "security headers (CSP, HSTS, X-Content-Type-Options, "
                    "X-Frame-Options, Referrer-Policy)."
                )
            findings.append(report)
        return findings
