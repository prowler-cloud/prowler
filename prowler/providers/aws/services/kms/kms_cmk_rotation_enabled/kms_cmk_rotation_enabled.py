from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)


class kms_cmk_rotation_enabled(Check):
    """Check if KMS Customer Managed Keys (CMKs) have automatic rotation enabled."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the kms_cmk_rotation_enabled check.

        Returns:
            list[Check_Report_AWS]: List of findings for the check.
        """
        findings = []
        findings.extend(
            generate_scan_error_reports(
                metadata=self.metadata(),
                action_text="customer-managed keys have automatic rotation enabled",
                client=kms_client,
            )
        )

        for key in kms_client.keys:
            if is_key_detail_unretrieved(key):
                findings.append(
                    generate_describe_error_report(
                        metadata=self.metadata(),
                        key=key,
                        action_text="customer-managed keys have automatic rotation enabled",
                    )
                )
                continue

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
