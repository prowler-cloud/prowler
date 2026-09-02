from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)


class kms_cmk_are_used(Check):
    def execute(self):
        findings = []
        findings.extend(
            generate_scan_error_reports(
                metadata=self.metadata(),
                action_text="customer-managed keys are in use or scheduled for deletion",
                client=kms_client,
            )
        )

        for key in kms_client.keys:
            if is_key_detail_unretrieved(key):
                findings.append(
                    generate_describe_error_report(
                        metadata=self.metadata(),
                        key=key,
                        action_text="customer-managed keys are in use or scheduled for deletion",
                    )
                )
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
