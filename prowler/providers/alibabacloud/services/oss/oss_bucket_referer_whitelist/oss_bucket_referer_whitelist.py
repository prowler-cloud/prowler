"""
Check: oss_bucket_referer_whitelist

Ensures that OSS buckets have referer whitelist configured and do not allow empty referers.
Referer whitelisting prevents hotlinking and unauthorized access from unknown sources.

Risk Level: LOW
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_referer_whitelist(Check):
    """Check if OSS buckets have referer whitelist configured properly"""

    def execute(self):
        """Execute the oss_bucket_referer_whitelist check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.referer_config:
                allow_empty = bucket.referer_config.get("AllowEmpty", True)
                referer_list = bucket.referer_config.get("RefererList", [])

                if allow_empty and (not referer_list or len(referer_list) == 0):
                    report.status = "FAIL"
                    report.status_extended = f"OSS bucket {bucket.name} allows empty referers and has no referer whitelist. Configure referer whitelist and disable empty referers to prevent hotlinking."
                elif allow_empty:
                    report.status = "FAIL"
                    report.status_extended = f"OSS bucket {bucket.name} allows empty referers. Disable empty referers to improve security."
                elif not referer_list or len(referer_list) == 0:
                    report.status = "FAIL"
                    report.status_extended = f"OSS bucket {bucket.name} has no referer whitelist configured. Configure referer whitelist to control access."
                else:
                    report.status = "PASS"
                    report.status_extended = f"OSS bucket {bucket.name} has proper referer whitelist configuration (AllowEmpty: False, {len(referer_list)} referer(s))."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} has no referer configuration. Configure referer whitelist to prevent hotlinking."

            findings.append(report)

        return findings
