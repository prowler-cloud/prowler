from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

# Agent Registry has its own IAM namespace and managed policy; BedrockAgentCoreFullAccess does not cover it.
FULL_ACCESS_POLICY_NAMES = ("BedrockAgentCoreFullAccess", "AgentRegistryFullAccess")


class bedrockagentcore_full_access_policy_attached(Check):
    """Ensure IAM roles do not have the AWS-managed Bedrock AgentCore full access policies attached.

    This check evaluates whether IAM roles (excluding service roles) have the
    BedrockAgentCoreFullAccess or AgentRegistryFullAccess AWS-managed policy attached.
    - PASS: The IAM role has neither policy attached.
    - FAIL: The IAM role has at least one of the policies attached.
    - MANUAL: The IAM roles could not be listed.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if iam_client.roles is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.role_arn_template
            report.status = "MANUAL"
            report.status_extended = (
                "IAM roles could not be listed, so this check could not be evaluated."
            )
            return [report]

        for role in iam_client.roles:
            if role.is_service_role:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region
            # Partition-independent: arn:aws:, arn:aws-us-gov: and arn:aws-cn: all carry ":iam::aws:policy/".
            attached = sorted(
                policy_arn.rsplit("/", 1)[-1]
                for policy_arn in (
                    policy.get("PolicyArn", "") for policy in role.attached_policies
                )
                if ":iam::aws:policy/" in policy_arn
                and policy_arn.rsplit("/", 1)[-1] in FULL_ACCESS_POLICY_NAMES
            )
            if attached:
                report.status = "FAIL"
                report.status_extended = f"IAM Role {role.name} has {' and '.join(attached)} policy attached."
            else:
                report.status = "PASS"
                report.status_extended = f"IAM Role {role.name} does not have BedrockAgentCoreFullAccess or AgentRegistryFullAccess policy attached."
            findings.append(report)
        return findings
