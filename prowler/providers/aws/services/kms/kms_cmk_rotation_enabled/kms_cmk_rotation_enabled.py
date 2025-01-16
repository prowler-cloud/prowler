from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_rotation_enabled(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=key)
            # Only check enabled CMKs keys
            if (
                key.manager == "CUSTOMER"
                and key.state == "Enabled"
                and "SYMMETRIC" in key.spec
            ):
                if key.rotation_enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"KMS CMK {key.id} has automatic rotation enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS CMK {key.id} has automatic rotation disabled."
                    )
                findings.append(report)
        return findings
