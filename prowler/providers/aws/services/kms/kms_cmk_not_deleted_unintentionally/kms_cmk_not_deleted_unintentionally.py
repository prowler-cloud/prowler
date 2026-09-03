from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)


class kms_cmk_not_deleted_unintentionally(Check):
    """Check if KMS Customer Managed Keys (CMKs) are not scheduled for deletion unintentionally."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the kms_cmk_not_deleted_unintentionally check.

        Returns:
            list[Check_Report_AWS]: List of findings for the check.
        """
        findings = []
        findings.extend(
            generate_scan_error_reports(
                metadata=self.metadata(),
                action_text="customer-managed keys are not unintentionally scheduled for deletion",
                client=kms_client,
            )
        )

        for key in kms_client.keys:
            if is_key_detail_unretrieved(key):
                findings.append(
                    generate_describe_error_report(
                        metadata=self.metadata(),
                        key=key,
                        action_text="customer-managed keys are not unintentionally scheduled for deletion",
                    )
                )
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
