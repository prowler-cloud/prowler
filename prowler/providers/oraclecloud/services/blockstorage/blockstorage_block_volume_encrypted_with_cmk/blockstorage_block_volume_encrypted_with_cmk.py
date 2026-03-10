"""Check if Block Volumes are encrypted with Customer Managed Keys."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_block_volume_encrypted_with_cmk(Check):
    """Check if Block Volumes are encrypted with Customer Managed Keys."""

    def execute(self) -> Check_Report_OCI:
        """Execute the blockstorage_block_volume_encrypted_with_cmk check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for volume in blockstorage_client.volumes:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=volume,
                region=volume.region,
                resource_name=volume.name,
                resource_id=volume.id,
                compartment_id=volume.compartment_id,
            )

            if volume.kms_key_id is not None:
                report.status = "PASS"
                report.status_extended = f"Block volume {volume.name} is encrypted with a Customer Managed Key (CMK)."
            else:
                report.status = "FAIL"
                report.status_extended = f"Block volume {volume.name} is not encrypted with a Customer Managed Key (uses Oracle-managed encryption)."

            findings.append(report)

        return findings
