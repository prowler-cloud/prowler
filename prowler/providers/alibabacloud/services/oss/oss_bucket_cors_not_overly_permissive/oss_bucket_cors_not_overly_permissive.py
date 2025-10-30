from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_cors_not_overly_permissive(Check):
    def execute(self):
        findings = []
        for bucket in oss_client.buckets.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=bucket
            )
            if not bucket.cors_rules or len(bucket.cors_rules) == 0:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} does not have CORS rules configured."
                )
            else:
                overly_permissive = False
                for rule in bucket.cors_rules:
                    allowed_origins = rule.get("AllowedOrigin", [])
                    if "*" in allowed_origins:
                        overly_permissive = True
                        break
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} has overly permissive CORS rules allowing all origins."
                if not overly_permissive:
                    report.status = "PASS"
                    report.status_extended = f"OSS bucket {bucket.name} has appropriately restrictive CORS rules."
            findings.append(report)
        return findings
