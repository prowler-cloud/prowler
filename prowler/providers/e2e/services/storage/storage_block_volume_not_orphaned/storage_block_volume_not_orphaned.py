from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.storage.storage_client import storage_client


class storage_block_volume_not_orphaned(Check):
    """Ensure available block volumes are attached to a node."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for volume in storage_client.block_volumes:
            report = CheckReportE2e(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = (
                f"Block volume {volume.name} is attached or not in an available orphaned state."
            )
            if volume.status == "Available" and not volume.is_attached:
                report.status = "FAIL"
                report.status_extended = (
                    f"Block volume {volume.name} is available and not attached to any node."
                )
            findings.append(report)
        return findings
