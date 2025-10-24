"""
Check: oss_bucket_lifecycle_rules

Ensures that OSS buckets have lifecycle rules configured to manage object lifecycle and optimize costs.
Lifecycle rules automatically transition or delete objects based on age.

Risk Level: LOW
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_lifecycle_rules(Check):
    """Check if OSS buckets have lifecycle rules configured"""

    def execute(self):
        """Execute the oss_bucket_lifecycle_rules check"""
        findings = []

        for bucket_arn, bucket in oss_client.buckets.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.account_uid = oss_client.account_id
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            if bucket.lifecycle_rules and len(bucket.lifecycle_rules) > 0:
                report.status = "PASS"
                report.status_extended = f"OSS bucket {bucket.name} has {len(bucket.lifecycle_rules)} lifecycle rule(s) configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"OSS bucket {bucket.name} does not have lifecycle rules configured. Configure lifecycle rules to manage object lifecycle and optimize storage costs."

            findings.append(report)

        return findings
