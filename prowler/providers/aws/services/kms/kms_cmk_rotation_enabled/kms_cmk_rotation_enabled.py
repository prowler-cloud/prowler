from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_cmk_rotation_enabled(Check):
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
            report.status_extended = f"KMS keys could not be listed in region {region} ({error}); verify manually that customer-managed keys have automatic rotation enabled."
            findings.append(report)

        for key in kms_client.keys:
            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            # Only check enabled CMKs keys
            if (
                key.manager == "CUSTOMER"
                and key.state == "Enabled"
                and key.spec
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
