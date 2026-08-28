from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class sagemaker_full_access_policy_attached(Check):
    """Ensure that IAM roles do not have the AmazonSageMakerFullAccess managed policy attached.

    This check evaluates whether IAM roles have the AmazonSageMakerFullAccess
    AWS-managed policy attached, which grants broad SageMaker and
    supporting-service permissions and violates the principle of least
    privilege.

    Only AWS service-linked roles are excluded, identified by the
    ``aws-service-role`` path in their ARN, since their permissions are managed
    by AWS and cannot be changed by the account owner. Customer-created service
    roles are evaluated: a SageMaker execution role is trusted by
    ``sagemaker.amazonaws.com`` alone, and is exactly where this policy is
    typically attached.
    - PASS: The IAM role does not have the AmazonSageMakerFullAccess policy attached.
    - FAIL: The IAM role has the AmazonSageMakerFullAccess policy attached.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                if "aws-service-role" not in role.arn:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                    report.region = iam_client.region
                    report.status = "PASS"
                    report.status_extended = f"IAM Role {role.name} does not have AmazonSageMakerFullAccess policy attached."
                    for policy in role.attached_policies:
                        if (
                            policy["PolicyArn"]
                            == "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"IAM Role {role.name} has AmazonSageMakerFullAccess policy attached."
                            break
                    findings.append(report)
        return findings
