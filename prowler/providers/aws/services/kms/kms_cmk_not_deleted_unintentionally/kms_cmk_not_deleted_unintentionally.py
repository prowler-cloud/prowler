from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_not_deleted_unintentionally(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            if key.manager == "CUSTOMER":
                if key.state != "Disabled" or kms_client.provider.scan_unused_services:
                    report = Check_Report_AWS(self.metadata())
                    report.region = key.region
                    report.resource_tags = key.tags
                    report.status = "PASS"
                    report.status_extended = (
                        f"KMS CMK {key.id} is not scheduled for deletion."
                    )
                    report.resource_id = key.id
                    report.resource_arn = key.arn
                    if key.state == "PendingDeletion":
                        report.status = "FAIL"
                        report.status_extended = f"KMS CMK {key.id} is scheduled for deletion, revert it if it was unintentionally."
                    findings.append(report)
        return findings
