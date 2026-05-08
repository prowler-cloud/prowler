from collections import Counter

from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.published.published_client import (
    published_client,
)


class published_app_no_secrets_in_frontend_bundle(Check):
    """No service-role keys or third-party secrets must be bundled into the
    published Lovable app's frontend JavaScript."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for inspection in published_client.inspections.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=inspection)
            if not inspection.reachable:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not reach published app {inspection.app_name}; "
                    "could not scan frontend bundle for secrets."
                )
            elif not inspection.bundles_inspected:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not locate JS bundles for {inspection.app_name}; "
                    "frontend secret scan was skipped."
                )
            elif inspection.leaked_secrets:
                counts = Counter(s["type"] for s in inspection.leaked_secrets)
                summary = ", ".join(
                    f"{count} {label}" for label, count in counts.items()
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Published app {inspection.app_name} bundles secret-like "
                    f"values in its frontend JavaScript ({summary}). Anything "
                    "shipped to the browser must be considered compromised."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Published app {inspection.app_name} did not match any "
                    "high-confidence secret patterns in scanned JS bundles "
                    f"({len(inspection.bundles_inspected)} bundle(s))."
                )
            findings.append(report)
        return findings
