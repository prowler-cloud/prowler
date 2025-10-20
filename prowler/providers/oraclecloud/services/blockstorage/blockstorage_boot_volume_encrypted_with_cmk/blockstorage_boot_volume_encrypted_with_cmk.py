"""Check Ensure Boot Volumes are encrypted with Customer Managed Key."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.blockstorage.blockstorage_client import (
    blockstorage_client,
)


class blockstorage_boot_volume_encrypted_with_cmk(Check):
    """Check Ensure Boot Volumes are encrypted with Customer Managed Key."""

    def execute(self) -> Check_Report_OCI:
        """Execute the blockstorage_boot_volume_encrypted_with_cmk check."""
        findings = []

        for resource in blockstorage_client.boot_volumes:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=resource,
                region=resource.region,
                resource_name=resource.name,
                resource_id=resource.id,
                compartment_id=resource.compartment_id,
            )

            if resource.kms_key_id is not None:
                report.status = "PASS"
                report.status_extended = f"Boot Volume {resource.name} is encrypted with Customer Managed Key."
            else:
                report.status = "FAIL"
                report.status_extended = f"Boot Volume {resource.name} is not encrypted with Customer Managed Key."

            findings.append(report)

        return findings
