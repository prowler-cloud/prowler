from collections import Counter
from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_volume_backup_exists(Check):
    """Ensure block storage volumes have at least one backup."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        # Build volume_id -> backup count mapping
        backup_counts = Counter(
            backup.volume_id for backup in blockstorage_client.backups
        )

        for volume in blockstorage_client.volumes:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            count = backup_counts.get(volume.id, 0)
            if count > 0:
                report.status = "PASS"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) has {count} backup(s)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) does not have any backups."
                )

            findings.append(report)

        return findings
