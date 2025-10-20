"""Check Ensure File Storage Systems are encrypted with Customer Managed Keys."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.filestorage.filestorage_client import (
    filestorage_client,
)


class filestorage_file_system_encrypted_with_cmk(Check):
    """Check Ensure File Storage Systems are encrypted with Customer Managed Keys."""

    def execute(self) -> Check_Report_OCI:
        """Execute the filestorage_file_system_encrypted_with_cmk check."""
        findings = []

        for resource in filestorage_client.file_systems:
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
                report.status_extended = (
                    f"{resource.name} meets the security requirement."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{resource.name} does not meet the security requirement."
                )

            findings.append(report)

        return findings
