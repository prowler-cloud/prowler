from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.inventory import (
    get_kms_inventory_error_reports,
    get_kms_key_detail_error_report,
)


class kms_key_not_publicly_accessible(Check):
    """Ensure customer-managed KMS keys are not publicly accessible."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the KMS key public-access check.

        Returns:
            list[Check_Report_AWS]: Reports for customer-managed keys and any
            incomplete KMS inventory evidence.
        """
        findings = get_kms_inventory_error_reports(self.metadata(), kms_client)
        for key in kms_client.keys:
            if not key.detail_retrieved:
                findings.append(get_kms_key_detail_error_report(self.metadata(), key))
                continue
            if (
                key.manager == "CUSTOMER"
                and key.state == "Enabled"
                and key.policy is None
                and key.policy_fetch_error
            ):
                report = Check_Report_AWS(metadata=self.metadata(), resource=key)
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS key {key.id} policy could not be fetched "
                    f"({key.policy_fetch_error}); public access cannot be verified."
                )
                findings.append(report)
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
