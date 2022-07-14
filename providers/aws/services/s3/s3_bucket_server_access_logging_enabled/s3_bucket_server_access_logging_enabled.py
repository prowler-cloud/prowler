from lib.check.models import Check, Check_Report
from providers.aws.services.s3.s3_service import s3_client


class s3_bucket_server_access_logging_enabled(Check):
    def execute(self):
        findings = []
        for regional_client in s3_client.regional_clients:
            region = regional_client.region
            if hasattr(regional_client, "buckets"):
                if regional_client.buckets:
                    for bucket in regional_client.buckets:
                        if "LoggingEnabled" in regional_client.get_bucket_logging(
                            Bucket=bucket["Name"]
                        ):
                            report = Check_Report(self.metadata)
                            report.region = region
                            report.status = "PASS"
                            report.status_extended = f"S3 Bucket {bucket['Name']} has server access logging enabled."
                            report.resource_id = bucket["Name"]
                        else:
                            report = Check_Report(self.metadata)
                            report.region = region
                            report.status = "FAIL"
                            report.status_extended = f"S3 Bucket {bucket['Name']} has server access logging disabled."
                            report.resource_id = bucket["Name"]
                        findings.append(report)
                else:
                    report = Check_Report(self.metadata)
                    report.status = "PASS"
                    report.status_extended = "There are no S3 buckets."
                    report.region = region
                    findings.append(report)

        return findings
