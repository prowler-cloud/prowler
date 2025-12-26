from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudstorage.cloudstorage_client import (
    cloudstorage_client,
)
from prowler.providers.gcp.services.logging.logging_client import logging_client


class cloudstorage_bucket_log_retention_policy_lock(Check):
    """
    Ensure Log Sink buckets have a Retention Policy with Bucket Lock enabled.

    - PASS: Log sink bucket has a retention policy and is locked.
    - FAIL: Log sink bucket has no retention policy, or it has one but is not locked.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        # Get Log Sink Buckets
        log_buckets = []
        for sink in logging_client.sinks:
            if "storage.googleapis.com" in sink.destination:
                log_buckets.append(sink.destination.split("/")[-1])
        for bucket in cloudstorage_client.buckets:
            if bucket.name in log_buckets:
                report = Check_Report_GCP(metadata=self.metadata(), resource=bucket)
                report.status = "FAIL"
                report.status_extended = (
                    f"Log Sink Bucket {bucket.name} has no Retention Policy."
                )
                if bucket.retention_policy:
                    report.status = "FAIL"
                    report.status_extended = f"Log Sink Bucket {bucket.name} has a Retention Policy but without Bucket Lock."
                    if bucket.retention_policy.is_locked:
                        report.status = "PASS"
                        report.status_extended = f"Log Sink Bucket {bucket.name} has a Retention Policy with Bucket Lock."
                findings.append(report)

        return findings
