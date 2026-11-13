from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    get_kms_inventory_error_reports,
    get_kms_key_detail_error_report,
)


class kms_cmk_not_deleted_unintentionally(Check):
    """Ensure customer-managed KMS keys are not pending deletion."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS key deletion check.

        Returns:
            list[Check_Report_AWS]: Reports for customer-managed keys and any
            incomplete KMS inventory evidence.
        """
        findings = get_kms_inventory_error_reports(self.metadata(), kms_client)
        for key in kms_client.keys:
            if not key.detail_retrieved:
                findings.append(get_kms_key_detail_error_report(self.metadata(), key))
                continue
            if key.manager == "CUSTOMER":
                if key.state != "Disabled" or kms_client.provider.scan_unused_services:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                    report.status = "PASS"
                    report.status_extended = (
                        f"KMS CMK {key.id} is not scheduled for deletion."
                    )
                    if key.state == "PendingDeletion":
                        report.status = "FAIL"
                        report.status_extended = f"KMS CMK {key.id} is scheduled for deletion, revert it if it was unintentionally."
                    findings.append(report)
        return findings
