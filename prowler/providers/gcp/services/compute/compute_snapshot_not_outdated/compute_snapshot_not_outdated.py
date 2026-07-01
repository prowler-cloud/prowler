from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_snapshot_not_outdated(Check):
    """Check that Compute Engine disk snapshots are not outdated.

    This check ensures Compute Engine disk snapshots are within the configured
    age threshold (default 90 days) to help control storage costs and limit
    exposure from stale data.

    - PASS: Snapshot is not outdated (within the acceptable age threshold).
    - FAIL: Snapshot is outdated (exceeds the configured age threshold).
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        max_snapshot_age_days = compute_client.audit_config.get(
            "max_snapshot_age_days", 90
        )

        current_time = datetime.now(timezone.utc)

        for snapshot in compute_client.snapshots:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=snapshot,
                location="global",
            )

            if snapshot.creation_timestamp is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Disk snapshot {snapshot.name} timestamp could not be retrieved "
                    "and cannot be evaluated for age."
                )
                findings.append(report)
                continue

            snapshot_age = (current_time - snapshot.creation_timestamp).days

            if snapshot_age > max_snapshot_age_days:
                report.status = "FAIL"
                report.status_extended = (
                    f"Disk snapshot {snapshot.name} is {snapshot_age} days old, "
                    f"exceeding the {max_snapshot_age_days} day threshold."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Disk snapshot {snapshot.name} is {snapshot_age} days old, "
                    f"within the {max_snapshot_age_days} day threshold."
                )

            findings.append(report)

        return findings
