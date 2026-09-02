from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_not_multi_region(Check):
    """kms_cmk_not_multi_region verifies if a KMS key is multi-regional"""

    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        for region, error in sorted(
            getattr(kms_client, "keys_scan_errors", {}).items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "key/unknown"
            report.resource_arn = f"arn:{kms_client.audited_partition}:kms:{region}:{kms_client.audited_account}:key/unknown"
            report.status = "MANUAL"
            report.status_extended = f"KMS keys could not be listed in region {region} ({error}); verify manually that customer-managed keys are not configured as multi-region."
            findings.append(report)

        for key in kms_client.keys:
            if key.manager == "CUSTOMER" and key.state == "Enabled":
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "PASS"
                report.status_extended = f"KMS CMK {key.id} is a single-region key."

                if key.multi_region:
                    report.status = "FAIL"
                    report.status_extended = f"KMS CMK {key.id} is a multi-region key."

                findings.append(report)

        return findings
