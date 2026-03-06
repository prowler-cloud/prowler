from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_volume_not_unattached(Check):
    """Ensure block storage volumes are attached to at least one instance."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for volume in blockstorage_client.volumes:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            attachment_count = len(volume.attachments)
            if attachment_count > 0:
                report.status = "PASS"
                report.status_extended = f"Volume {volume.name} ({volume.id}) is attached to {attachment_count} instance(s)."
            elif volume.status != "available":
                report.status = "PASS"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) is not attached but is in "
                    f"'{volume.status}' state (not idle)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Volume {volume.name} ({volume.id}) is unattached and may be orphaned."

            findings.append(report)

        return findings
