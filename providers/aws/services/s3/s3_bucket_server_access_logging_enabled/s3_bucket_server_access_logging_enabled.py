from lib.check.models import Check, Check_Report
from providers.aws.services.s3.s3_service import s3_client


class s3_bucket_server_access_logging_enabled(Check):
    def execute(self):
        findings = []
        for regional_client in s3_client.regional_clients:
            region = regional_client.region
            if regional_client.buckets:
                for bucket in regional_client.buckets:
                    report = Check_Report(self.metadata)
                    report.region = region
                    report.resource_id = bucket.name
                    if bucket.logging:
                        report.status = "PASS"
                        report.status_extended = f"S3 Bucket {bucket.name} has server access logging enabled."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} has server access logging disabled."
                    findings.append(report)
            else:
                report = Check_Report(self.metadata)
                report.status = "PASS"
                report.status_extended = "There are no S3 buckets."
                report.region = region
                findings.append(report)

        return findings
