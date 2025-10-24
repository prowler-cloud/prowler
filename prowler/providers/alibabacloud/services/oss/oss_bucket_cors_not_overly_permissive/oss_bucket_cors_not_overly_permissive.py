"""
Check: oss_bucket_cors_not_overly_permissive

Ensures that OSS bucket CORS (Cross-Origin Resource Sharing) rules are not overly permissive.
Overly permissive CORS rules can allow unauthorized websites to access bucket resources.

Risk Level: MEDIUM
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_cors_not_overly_permissive(Check):
    """Check if OSS bucket CORS rules are not overly permissive"""

    def execute(self):
        """Execute the oss_bucket_cors_not_overly_permissive check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if not bucket.cors_rules or len(bucket.cors_rules) == 0:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} does not have CORS rules configured."
            else:
                # Check if any CORS rule allows all origins (*)
                overly_permissive = False
                for rule in bucket.cors_rules:
                    allowed_origins = rule.get("AllowedOrigin", [])
                    if "*" in allowed_origins:
                        overly_permissive = True
                        break

                if overly_permissive:
                    report.status = "FAIL"
                    report.status_extended = f"OSS bucket {bucket.name} has overly permissive CORS rules allowing all origins (*). Restrict CORS rules to specific trusted origins."
                else:
                    report.status = "PASS"
                    report.status_extended = f"OSS bucket {bucket.name} has appropriately restrictive CORS rules."

            findings.append(report)

        return findings
