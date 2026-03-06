from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_volume_encryption_enabled(Check):
    """Ensure block storage volumes have encryption enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for volume in blockstorage_client.volumes:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            if volume.is_encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) has encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Volume {volume.name} ({volume.id}) does not have encryption enabled."

            findings.append(report)

        return findings
