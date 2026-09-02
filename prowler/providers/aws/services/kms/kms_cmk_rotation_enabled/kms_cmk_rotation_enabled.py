from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    get_kms_inventory_error_reports,
    get_kms_key_detail_error_report,
)


class kms_cmk_rotation_enabled(Check):
    def execute(self):
        findings = get_kms_inventory_error_reports(self.metadata(), kms_client)
        for key in kms_client.keys:
            if not key.detail_retrieved:
                findings.append(get_kms_key_detail_error_report(self.metadata(), key))
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
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
