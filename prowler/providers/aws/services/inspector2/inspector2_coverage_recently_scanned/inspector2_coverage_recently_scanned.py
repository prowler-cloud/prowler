from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)

PENDING_SCAN_REASONS = {
    "PENDING_INITIAL_SCAN",
    "PENDING_REVIVAL_SCAN",
    "SCAN_IN_PROGRESS",
}


class inspector2_coverage_recently_scanned(Check):
    """Ensure Inspector2 scanned every actively covered resource within the configured days."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        max_days = inspector2_client.audit_config.get(
            "inspector2_max_days_since_last_scan", 3
        )
        now = datetime.now(timezone.utc)
        for inspector in inspector2_client.inspectors:
            if inspector.status != "ENABLED":
                continue
            if inspector.coverage is None:
                report = Check_Report_AWS(metadata=self.metadata(), resource=inspector)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Inspector2 coverage could not be retrieved in region {inspector.region}; "
                    "verify the inspector2:ListCoverage permission."
                )
                findings.append(report)
                continue
            for resource in inspector.coverage:
                if resource.scan_status_code != "ACTIVE":
                    continue
                if (
                    resource.last_scanned_at is None
                    and resource.scan_status_reason in PENDING_SCAN_REASONS
                ):
                    continue
                report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
                if resource.last_scanned_at is None:
                    report.status = "FAIL"
                    report.status_extended = f"{resource.resource_type} {resource.id} has no recorded Inspector2 scan."
                else:
                    days = (now - resource.last_scanned_at).days
                    if days > max_days:
                        report.status = "FAIL"
                        report.status_extended = f"{resource.resource_type} {resource.id} was last scanned by Inspector2 {days} days ago, exceeding the {max_days} days allowed."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"{resource.resource_type} {resource.id} was last scanned by Inspector2 {days} days ago, within the {max_days} days allowed."
                findings.append(report)
        return findings
