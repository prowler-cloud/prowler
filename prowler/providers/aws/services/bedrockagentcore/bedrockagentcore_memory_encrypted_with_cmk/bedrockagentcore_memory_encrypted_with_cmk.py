from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.kms.kms_client import kms_client


class bedrockagentcore_memory_encrypted_with_cmk(Check):
    """Ensure Bedrock AgentCore memories are encrypted with a customer-managed KMS key.

    - PASS: The memory has `encryptionKeyArn` set to a customer-managed KMS key.
    - FAIL: The memory has no `encryptionKeyArn`, so it uses an AWS-owned key, or the key
      is an AWS-managed key.
    - MANUAL: Memories could not be listed in a region, the memory detail could not be
      retrieved, or the key manager could not be determined.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(
            bedrockagentcore_client.memories_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "memory/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:memory/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore memories could not be listed in region {region} ({error}); verify that the scanning identity is allowed to call bedrock-agentcore:ListMemories, and verify manually that every memory uses a customer-managed KMS key."
            findings.append(report)

        key_managers = {key.arn: key.manager for key in kms_client.keys}

        for memory in bedrockagentcore_client.memories.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=memory)
            memory_name = memory.name or memory.id
            key_arn = memory.encryption_key_arn
            key_manager = key_managers.get(key_arn)

            if not memory.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore memory {memory_name} encryption configuration could not be retrieved in region {memory.region}; verify that the scanning identity is allowed to call bedrock-agentcore:GetMemory, and verify manually that it uses a customer-managed KMS key."
            elif not key_arn:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore memory {memory_name} is not encrypted with a customer-managed KMS key in region {memory.region}."
            elif key_manager == "CUSTOMER" or self._is_key_from_another_account(
                key_arn
            ):
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore memory {memory_name} is encrypted with the customer-managed KMS key {key_arn} in region {memory.region}."
            elif key_manager == "AWS":
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore memory {memory_name} is encrypted with the AWS-managed KMS key {key_arn} instead of a customer-managed KMS key in region {memory.region}."
            else:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore memory {memory_name} is encrypted with the KMS key {key_arn} in region {memory.region}, but the key details could not be retrieved; verify that the scanning identity is allowed to call kms:ListKeys and kms:DescribeKey, and verify manually that it is a customer-managed KMS key."
            findings.append(report)

        return findings

    @staticmethod
    def _is_key_from_another_account(key_arn: str) -> bool:
        """Tell whether a KMS key belongs to an account other than the audited one.

        AWS-managed keys can only be used inside their own account, so a key shared
        from another account is always customer-managed.

        Args:
            key_arn: The ARN of the KMS key.

        Returns:
            True if the ARN names an account other than the audited one.
        """
        arn_parts = key_arn.split(":")
        return (
            len(arn_parts) > 4
            and bool(arn_parts[4])
            and arn_parts[4] != bedrockagentcore_client.audited_account
        )
