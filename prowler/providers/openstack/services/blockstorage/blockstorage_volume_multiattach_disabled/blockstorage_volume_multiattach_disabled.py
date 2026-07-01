from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_volume_multiattach_disabled(Check):
    """Ensure block storage volumes do not have multi-attach enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for volume in blockstorage_client.volumes:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=volume)
            if not volume.is_multiattach:
                report.status = "PASS"
                report.status_extended = f"Volume {volume.name} ({volume.id}) does not have multi-attach enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) has multi-attach enabled, "
                    f"allowing simultaneous attachment to multiple instances."
                )

            findings.append(report)

        return findings
