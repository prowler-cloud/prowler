from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_not_deleted_unintentionally(Check):
    def execute(self):
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
            report.status_extended = f"KMS keys could not be listed in region {region} ({error}); verify manually that customer-managed keys are not unintentionally scheduled for deletion."
            findings.append(report)

        for key in kms_client.keys:
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
