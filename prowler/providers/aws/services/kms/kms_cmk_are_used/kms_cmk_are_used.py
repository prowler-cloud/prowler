from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    get_kms_inventory_error_reports,
    get_kms_key_detail_error_report,
)


class kms_cmk_are_used(Check):
    """Assess whether customer-managed KMS keys are in use."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS key usage check.

        Returns:
            list[Check_Report_AWS]: Reports for customer-managed keys and any
            incomplete KMS inventory evidence.
        """
        findings = get_kms_inventory_error_reports(self.metadata(), kms_client)
        for key in kms_client.keys:
            if not key.detail_retrieved:
                findings.append(get_kms_key_detail_error_report(self.metadata(), key))
                continue
            # Only check CMKs keys
            if key.manager == "CUSTOMER":
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                if key.state != "Enabled":
                    if key.state == "PendingDeletion":
                        report.status = "PASS"
                        report.status_extended = f"KMS CMK {key.id} is not being used but it has scheduled deletion."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"KMS CMK {key.id} is not being used."
                else:
                    report.status = "PASS"
                    report.status_extended = f"KMS CMK {key.id} is being used."
                findings.append(report)
        return findings
