from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_block_volume_not_orphaned(Check):
    """Check that available block volumes are attached to a node."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for volume in storage_client.block_volumes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = f"Block volume {volume.name} is attached or not in an available orphaned state."
            if volume.status == "Available" and not volume.is_attached:
                report.status = "FAIL"
                report.status_extended = f"Block volume {volume.name} is available and not attached to any node."
            findings.append(report)
        return findings
