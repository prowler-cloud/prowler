from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_snapshot_not_orphaned(Check):
    """Ensure block storage snapshots reference existing volumes."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        # Build set of existing volume IDs
        existing_volume_ids = {volume.id for volume in blockstorage_client.volumes}

        for snapshot in blockstorage_client.snapshots:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=snapshot)
            if snapshot.volume_id in existing_volume_ids:
                report.status = "PASS"
                report.status_extended = f"Snapshot {snapshot.name} ({snapshot.id}) references existing volume {snapshot.volume_id}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Snapshot {snapshot.name} ({snapshot.id}) references non-existent volume "
                    f"{snapshot.volume_id} and may be orphaned."
                )

            findings.append(report)

        return findings
