from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    get_kms_inventory_error_reports,
    get_kms_key_detail_error_report,
)


class kms_cmk_not_multi_region(Check):
    """Ensure customer-managed KMS keys are single-region."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS multi-region key check.

        Returns:
            list[Check_Report_AWS]: Reports for customer-managed keys and any
            incomplete KMS inventory evidence.
        """
        findings = get_kms_inventory_error_reports(self.metadata(), kms_client)

        for key in kms_client.keys:
            if not key.detail_retrieved:
                findings.append(get_kms_key_detail_error_report(self.metadata(), key))
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
