from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.logging.logging_client import logging_client
from prowler.providers.oraclecloud.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_bucket_logging_enabled(Check):
    """Ensure write level Object Storage logging is enabled for all buckets"""

    def execute(self):
        """Execute check to verify write-level logging is enabled for Object Storage buckets."""
        findings = []

        for bucket in objectstorage_client.buckets:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=bucket,
                region=bucket.region,
                resource_id=bucket.id,
                resource_name=bucket.name,
                compartment_id=bucket.compartment_id,
            )

            # Check if there is a write-level log configured for this bucket
            # A write log should have:
            # - source.service == 'objectstorage'
            # - source.category == 'write'
            # - source.resource == bucket.name
            has_write_logging = False
            has_read_logging = False
            for log in logging_client.logs:
                if (
                    log.source_service == "objectstorage"
                    and log.source_category == "write"
                    and log.source_resource == bucket.name
                    and log.region == bucket.region
                    and log.is_enabled
                ):
                    has_write_logging = True
                elif (
                    log.source_service == "objectstorage"
                    and log.source_category == "read"
                    and log.source_resource == bucket.name
                    and log.region == bucket.region
                    and log.is_enabled
                ):
                    has_read_logging = True

            if has_write_logging:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} has write-level logging enabled."
                )
            elif has_read_logging:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} has read-level logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} does not have write-level logging enabled."
                )

            findings.append(report)

        return findings
