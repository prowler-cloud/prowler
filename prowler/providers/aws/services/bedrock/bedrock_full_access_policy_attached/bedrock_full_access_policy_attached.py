from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class bedrock_full_access_policy_attached(Check):
    """Ensure that IAM roles do not have the AmazonBedrockFullAccess managed policy attached.

    This check evaluates whether IAM roles (excluding service roles) have the
    AmazonBedrockFullAccess AWS-managed policy attached, which grants excessive
    permissions and violates the principle of least privilege.
    - PASS: The IAM role does not have the AmazonBedrockFullAccess policy attached.
    - FAIL: The IAM role has the AmazonBedrockFullAccess policy attached.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                if not role.is_service_role:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=role)
                    report.region = iam_client.region
                    report.status = "PASS"
                    report.status_extended = f"IAM Role {role.name} does not have AmazonBedrockFullAccess policy attached."
                    for policy in role.attached_policies:
                        if (
                            policy["PolicyArn"]
                            == "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"IAM Role {role.name} has AmazonBedrockFullAccess policy attached."
                            break
                    findings.append(report)
        return findings
