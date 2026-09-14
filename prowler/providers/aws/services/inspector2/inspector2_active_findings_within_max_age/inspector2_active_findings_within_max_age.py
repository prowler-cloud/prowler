from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_active_findings_within_max_age(Check):
    """Ensure no Inspector2 finding stays active longer than the configured days."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        max_age_days = inspector2_client.audit_config.get(
            "inspector2_active_finding_max_age_days", 192
        )
        now = datetime.now(timezone.utc)
        for inspector in inspector2_client.inspectors:
            if inspector.status != "ENABLED":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=inspector)
            if inspector.findings is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Inspector2 findings could not be retrieved in region {inspector.region}; "
                    "verify the inspector2:ListFindings permission."
                )
                findings.append(report)
                continue
            stale_ages = [
                (now - finding.first_observed_at).days
                for finding in inspector.findings
                if finding.first_observed_at
                and (now - finding.first_observed_at).days > max_age_days
            ]
            if stale_ages:
                report.status = "FAIL"
                report.status_extended = (
                    f"Inspector2 has {len(stale_ages)} active findings in region {inspector.region} "
                    f"first observed more than {max_age_days} days ago, the oldest {max(stale_ages)} days ago."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Inspector2 has no active findings in region {inspector.region} "
                    f"first observed more than {max_age_days} days ago."
                )
            findings.append(report)
        return findings
