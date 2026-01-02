nano prowler/providers/aws/services/s3/s3_bucket_server_access_logging_enabled/s3_bucket_server_access_logging_enabled.pyfrom prowler.lib.check.models import Check, Check_Report_AWS from 
prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_server_access_logging_enabled(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.logging:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has server access logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has server access logging disabled."
                    "Without access logs, object-level access activity cannot be audited."
                )
            findings.append(report)

        return findings
