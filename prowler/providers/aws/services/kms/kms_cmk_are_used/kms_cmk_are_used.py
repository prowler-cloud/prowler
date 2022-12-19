from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_are_used(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            # Only check CMKs keys
            if key.manager == "CUSTOMER":
                report = Check_Report_AWS(self.metadata())
                report.region = key.region
                report.resource_id = key.id
                report.resource_arn = key.arn
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
