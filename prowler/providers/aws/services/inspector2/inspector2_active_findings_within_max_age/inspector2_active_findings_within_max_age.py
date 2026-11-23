from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)

DEFAULT_ACTIVE_FINDING_MAX_AGE_DAYS = 192


class inspector2_active_findings_within_max_age(Check):
    """Ensure no Inspector2 finding stays active longer than the configured days."""

    def execute(self) -> list[Check_Report_AWS]:
        """Report, per Region, whether any active finding is older than the allowed days."""
        findings = []
        max_age_days = inspector2_client.audit_config.get(
            "inspector2_active_finding_max_age_days",
            DEFAULT_ACTIVE_FINDING_MAX_AGE_DAYS,
        )
        now = datetime.now(timezone.utc)
        max_age = timedelta(days=max_age_days)
        for inspector in inspector2_client.inspectors:
            if inspector.status != "ENABLED":
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=inspector)
            if inspector.oldest_findings is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Inspector2 findings could not be retrieved in region {inspector.region}; "
                    "verify the inspector2:ListFindings permission."
                )
                findings.append(report)
                continue
            oldest_age = next(
                (
                    now - finding.first_observed_at
                    for finding in inspector.oldest_findings
                    if finding.first_observed_at
                ),
                None,
            )
            if oldest_age and oldest_age > max_age:
                report.status = "FAIL"
                report.status_extended = (
                    f"Inspector2 has active findings in region {inspector.region} "
                    f"first observed more than {max_age_days} days ago, the oldest "
                    f"{oldest_age.days} days ago."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Inspector2 has no active findings in region {inspector.region} "
                    f"first observed more than {max_age_days} days ago."
                )
            findings.append(report)
        return findings
