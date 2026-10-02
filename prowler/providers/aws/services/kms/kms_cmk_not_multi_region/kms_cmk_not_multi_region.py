from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)


class kms_cmk_not_multi_region(Check):
    """kms_cmk_not_multi_region verifies if a KMS key is multi-regional"""

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the kms_cmk_not_multi_region check.

        Returns:
            List[Check_Report_AWS]: List of findings for the check.
        """
        findings = []
        findings.extend(
            generate_scan_error_reports(
                metadata=self.metadata(),
                action_text="customer-managed keys are not configured as multi-region",
                client=kms_client,
            )
        )

        for key in kms_client.keys:
            if is_key_detail_unretrieved(key):
                findings.append(
                    generate_describe_error_report(
                        metadata=self.metadata(),
                        key=key,
                        action_text="customer-managed keys are not configured as multi-region",
                    )
                )
                continue

            if key.manager == "CUSTOMER" and key.state == "Enabled":
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "PASS"
                report.status_extended = f"KMS CMK {key.id} is a single-region key."

                if key.multi_region:
                    report.status = "FAIL"
                    report.status_extended = f"KMS CMK {key.id} is a multi-region key."

                findings.append(report)

        return findings
