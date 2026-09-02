from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    generate_describe_error_report,
    generate_scan_error_reports,
    is_key_detail_unretrieved,
)


class kms_key_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        findings.extend(
            generate_scan_error_reports(
                metadata=self.metadata(),
                action_text="key policies do not allow public access",
                client=kms_client,
            )
        )

        for key in kms_client.keys:
            if is_key_detail_unretrieved(key):
                findings.append(
                    generate_describe_error_report(
                        metadata=self.metadata(),
                        key=key,
                        action_text="key policies do not allow public access",
                    )
                )
                continue

            if (
                key.manager == "CUSTOMER"
                and key.state == "Enabled"
                and key.policy is not None
            ):  # only customer KMS have policies
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "PASS"
                report.status_extended = f"KMS key {key.id} is not exposed to Public."
                # If the "Principal" element value is set to { "AWS": "*" } and the policy statement is not using any Condition clauses to filter the access, the selected AWS KMS master key is publicly accessible.
                if is_policy_public(
                    key.policy,
                    kms_client.audited_account,
                    not_allowed_actions=[],
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"KMS key {key.id} may be publicly accessible."
                    )
                findings.append(report)
        return findings
