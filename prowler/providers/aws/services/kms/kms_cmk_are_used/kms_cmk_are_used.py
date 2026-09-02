from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_are_used(Check):
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
            report.status_extended = f"KMS keys could not be listed in region {region} ({error}); verify manually that customer-managed keys are in use or scheduled for deletion."
            findings.append(report)

        for key in kms_client.keys:
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
