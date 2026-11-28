from unittest import mock

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    AgentCoreMemory,
)
from prowler.providers.aws.services.kms.kms_service import Key
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

MEMORY_ID = "test_memory-a1b2c3d4e5"
MEMORY_NAME = "test_memory"
MEMORY_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/{MEMORY_ID}"
KMS_KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab"
KMS_KEY_ARN = (
    f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/{KMS_KEY_ID}"
)
EXTERNAL_KMS_KEY_ARN = (
    f"arn:aws:kms:{AWS_REGION_US_EAST_1}:210987654321:key/{KMS_KEY_ID}"
)
CHECK_MODULE = "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_memory_encrypted_with_cmk.bedrockagentcore_memory_encrypted_with_cmk"


def _memory(
    encryption_key_arn=KMS_KEY_ARN,
    detail_retrieved=True,
    name=MEMORY_NAME,
    memory_id=MEMORY_ID,
):
    return AgentCoreMemory(
        id=memory_id,
        name=name,
        arn=f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/{memory_id}",
        region=AWS_REGION_US_EAST_1,
        encryption_key_arn=encryption_key_arn,
        detail_retrieved=detail_retrieved,
    )


def _key(manager="CUSTOMER"):
    return Key(
        id=KMS_KEY_ID,
        arn=KMS_KEY_ARN,
        region=AWS_REGION_US_EAST_1,
        manager=manager,
    )


def _run(memories=(), keys=(), scan_errors=None):
    client = mock.MagicMock()
    client.memories = {memory.arn: memory for memory in memories}
    client.memories_scan_errors = scan_errors or {}
    client.audited_partition = "aws"
    client.audited_account = AWS_ACCOUNT_NUMBER
    kms_client = mock.MagicMock()
    kms_client.keys = list(keys)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=client),
        mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_client),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_memory_encrypted_with_cmk.bedrockagentcore_memory_encrypted_with_cmk import (
            bedrockagentcore_memory_encrypted_with_cmk,
        )

        return bedrockagentcore_memory_encrypted_with_cmk().execute()


class Test_bedrockagentcore_memory_encrypted_with_cmk:
    def test_no_memories(self):
        assert _run() == []

    def test_memory_with_customer_managed_key_passes(self):
        result = _run([_memory()], keys=[_key()])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} is encrypted with the customer-managed KMS key {KMS_KEY_ARN} in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == MEMORY_ID
        assert result[0].resource_arn == MEMORY_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_memory_with_key_from_another_account_passes(self):
        result = _run([_memory(encryption_key_arn=EXTERNAL_KMS_KEY_ARN)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} is encrypted with the customer-managed KMS key {EXTERNAL_KMS_KEY_ARN} in region {AWS_REGION_US_EAST_1}."
        )

    def test_memory_without_key_fails(self):
        result = _run([_memory(encryption_key_arn=None)], keys=[_key()])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} is not encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == MEMORY_ID
        assert result[0].resource_arn == MEMORY_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_memory_with_aws_managed_key_fails(self):
        result = _run([_memory()], keys=[_key(manager="AWS")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} is encrypted with the AWS-managed KMS key {KMS_KEY_ARN} instead of a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )

    def test_memory_with_unknown_key_is_manual(self):
        result = _run([_memory()])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} is encrypted with the KMS key {KMS_KEY_ARN} in region {AWS_REGION_US_EAST_1}, but the key details could not be retrieved; verify that the scanning identity is allowed to call kms:ListKeys and kms:DescribeKey, and verify manually that it is a customer-managed KMS key."
        )

    def test_memory_with_undescribed_key_is_manual(self):
        result = _run([_memory()], keys=[_key(manager=None)])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "key details could not be retrieved" in result[0].status_extended

    def test_unretrieved_detail_is_manual(self):
        result = _run([_memory(encryption_key_arn=None, detail_retrieved=False)])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memory {MEMORY_NAME} encryption configuration could not be retrieved in region {AWS_REGION_US_EAST_1}; verify that the scanning identity is allowed to call bedrock-agentcore:GetMemory, and verify manually that it uses a customer-managed KMS key."
        )
        assert result[0].resource_id == MEMORY_ID

    def test_memory_without_name_is_reported_by_id(self):
        result = _run([_memory(name=None, detail_retrieved=False)])
        assert result[0].status == "MANUAL"
        assert f"memory {MEMORY_ID} " in result[0].status_extended

    def test_unlisted_region_is_manual(self):
        result = _run(
            [_memory()],
            keys=[_key()],
            scan_errors={AWS_REGION_EU_WEST_1: "AccessDeniedException"},
        )
        assert [finding.status for finding in result] == ["MANUAL", "PASS"]
        assert result[0].region == AWS_REGION_EU_WEST_1
        assert result[0].resource_id == "memory/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:memory/unknown"
        )
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore memories could not be listed in region {AWS_REGION_EU_WEST_1} (AccessDeniedException); verify that the scanning identity is allowed to call bedrock-agentcore:ListMemories, and verify manually that every memory uses a customer-managed KMS key."
        )

    def test_multiple_memories(self):
        result = _run(
            [
                _memory(),
                _memory(
                    encryption_key_arn=None,
                    name="other_memory",
                    memory_id="other_memory-f6g7h8i9j0",
                ),
            ],
            keys=[_key()],
        )
        assert [finding.status for finding in result] == ["PASS", "FAIL"]
        assert [finding.resource_id for finding in result] == [
            MEMORY_ID,
            "other_memory-f6g7h8i9j0",
        ]
