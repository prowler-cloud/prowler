from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_not_scheduled_for_deletion(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            # Only check Customer Managed Keys (CMKs)
            if key.manager == "CUSTOMER":
                report = Check_Report_AWS(self.metadata())
                report.region = key.region
                report.resource_id = key.id
                report.resource_arn = key.arn
                report.resource_tags = key.tags

                # Check if the key is scheduled for deletion
                if key.state == "PendingDeletion":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS CMK {key.id} is scheduled for deletion."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"KMS CMK {key.id} is not scheduled for deletion."
                    )

                findings.append(report)

        return findings
