"""
Check: ram_access_key_rotation

Ensures that RAM user access keys are rotated regularly (within 90 days).
Regular access key rotation reduces the risk of unauthorized access from compromised keys.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from datetime import datetime

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_access_key_rotation(Check):
    """Check if RAM user access keys are rotated within 90 days"""

    def execute(self):
        """Execute the ram_access_key_rotation check"""
        findings = []

        for user_arn, user in ram_client.users.items():
            for access_key in user.access_keys:
                resource = GenericAlibabaCloudResource(
                    id="unknown",
                    name="Unknown",
                    arn=f"{user.arn}/access-key/{access_key.access_key_id}",
                    region="global",
                )
                report = Check_Report_AlibabaCloud(
                    metadata=self.metadata(), resource=resource
                )

                report.account_uid = ram_client.account_id
                report.region = "global"
                report.resource_id = access_key.access_key_id
                report.resource_arn = (
                    f"{user.arn}/access-key/{access_key.access_key_id}"
                )

                # Check if access key is older than 90 days
                if access_key.create_date:
                    try:
                        create_date = datetime.fromisoformat(
                            access_key.create_date.replace("Z", "+00:00")
                        )
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days

                        if age_days <= 90:
                            report.status = "PASS"
                            report.status_extended = f"Access key {access_key.access_key_id} for user {user.name} is {age_days} days old (within the 90-day rotation period)."
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"Access key {access_key.access_key_id} for user {user.name} is {age_days} days old. Rotate access keys at least every 90 days."
                    except Exception:
                        report.status = "FAIL"
                        report.status_extended = f"Unable to determine age of access key {access_key.access_key_id} for user {user.name}. Ensure access keys are rotated regularly."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Access key {access_key.access_key_id} for user {user.name} has no creation date. Ensure access keys are rotated regularly."

                findings.append(report)

        return findings
