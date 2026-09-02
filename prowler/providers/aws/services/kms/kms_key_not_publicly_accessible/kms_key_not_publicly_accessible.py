from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_key_not_publicly_accessible(Check):
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
            report.status_extended = f"KMS keys could not be listed in region {region} ({error}); verify manually that key policies do not allow public access."
            findings.append(report)

        for key in kms_client.keys:
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
