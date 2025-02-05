from typing import List
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms import kms_client


class kms_cmk_not_multiregional(Check):
    """kms_cmk_not_multiregional verifies if a KMS key is multi-regional"""

    def execute(self) -> List[Check_Report_AWS]:

        findings = []

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
