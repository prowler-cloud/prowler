from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

critical_service = "kms"


class iam_policy_no_kms_decryption_actions(Check):
    """Check IAM policies for KMS decryption actions.

    This class verifies that IAM policies do not allow KMS decryption actions (kms:Decrypt or kms:ReEncryptFrom) on all resources.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the No KMS Decryption Actions check.

        Iterates over all IAM policies and checks if any of them allow KMS decryption actions.

        Returns:
            List[Check_Report_AWS]: A list of reports for each IAM policy that allows KMS decryption actions.
        """
        findings = []
        for policy in iam_client.policies:
            # Check only custom policies
            if policy.type == "Custom":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = policy.arn
                report.resource_id = policy.name
                report.resource_tags = policy.tags
                report.status = "PASS"
                report.status_extended = f"Custom Policy {policy.name} does not allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."

                if policy.document:
                    for statement in policy.document.get("Statement", []):
                        if (
                            statement.get("Effect") == "Allow"
                            and "Action" in statement
                            and (
                                "kms:Decrypt" in statement["Action"]
                                or "kms:ReEncryptFrom" in statement["Action"]
                            )
                            and "Resource" in statement
                            and "*" in statement["Resource"]
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Custom Policy {policy.name} does allow kms:Decrypt or kms:ReEncryptFrom privileges on all resources."

                findings.append(report)

        return findings
