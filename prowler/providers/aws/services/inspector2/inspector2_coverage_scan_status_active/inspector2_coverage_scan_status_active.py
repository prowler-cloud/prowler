from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)

NOT_APPLICABLE_SCAN_REASONS = {
    "EC2_INSTANCE_STOPPED",
    "EXCLUDED_BY_TAG",
    "NO_RESOURCES_FOUND",
    "PENDING_DISABLE",
    "RESOURCE_TERMINATED",
    "SCAN_ELIGIBILITY_EXPIRED",
}


class inspector2_coverage_scan_status_active(Check):
    """Ensure Inspector2 is actively scanning every covered resource."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
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
                if resource.scan_status_reason in NOT_APPLICABLE_SCAN_REASONS:
                    continue
                report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
                if resource.scan_status_code == "ACTIVE":
                    report.status = "PASS"
                    report.status_extended = f"Inspector2 is actively scanning {resource.resource_type} {resource.id}."
                else:
                    report.status = "FAIL"
                    reason = resource.scan_status_reason or "no reason reported"
                    report.status_extended = f"Inspector2 is not scanning {resource.resource_type} {resource.id}: {reason}."
                findings.append(report)
        return findings
