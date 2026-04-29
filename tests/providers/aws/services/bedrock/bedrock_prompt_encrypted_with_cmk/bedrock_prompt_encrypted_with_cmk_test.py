from unittest import mock

import botocore

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

PROMPT_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/test-prompt-id"
)
PROMPT_ID = "test-prompt-id"
PROMPT_NAME = "test-prompt"
KMS_KEY_ARN = (
    f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/"
    "12345678-1234-1234-1234-123456789012"
)


def mock_make_api_call_with_cmk(self, operation_name, kwarg):
    """Mock API call returning a prompt encrypted with a customer-managed KMS key."""
    if operation_name == "ListPrompts":
        return {
            "promptSummaries": [
                {
                    "id": PROMPT_ID,
                    "name": PROMPT_NAME,
                    "arn": PROMPT_ARN,
                }
            ]
        }
    elif operation_name == "GetPrompt":
        return {
            "id": PROMPT_ID,
            "name": PROMPT_NAME,
            "arn": PROMPT_ARN,
            "customerEncryptionKeyArn": KMS_KEY_ARN,
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_without_cmk(self, operation_name, kwarg):
    """Mock API call returning a prompt without a customer-managed KMS key."""
    if operation_name == "ListPrompts":
        return {
            "promptSummaries": [
                {
                    "id": PROMPT_ID,
                    "name": PROMPT_NAME,
                    "arn": PROMPT_ARN,
                }
            ]
        }
    elif operation_name == "GetPrompt":
        return {
            "id": PROMPT_ID,
            "name": PROMPT_NAME,
            "arn": PROMPT_ARN,
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_prompt_encrypted_with_cmk:
    """Test suite for the bedrock_prompt_encrypted_with_cmk check."""

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=lambda self, op, kwarg: make_api_call(self, op, kwarg),
    )
    def test_no_prompts(self):
        """Test when no prompts exist."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk import (
                bedrock_prompt_encrypted_with_cmk,
            )

            check = bedrock_prompt_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 0

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_with_cmk,
    )
    def test_prompt_encrypted_with_cmk(self):
        """Test when a prompt is encrypted with a customer-managed KMS key."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk import (
                bedrock_prompt_encrypted_with_cmk,
            )

            check = bedrock_prompt_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt {PROMPT_NAME} is encrypted with a customer-managed KMS key."
            )
            assert result[0].resource_id == PROMPT_ID
            assert result[0].resource_arn == PROMPT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_without_cmk,
    )
    def test_prompt_not_encrypted_with_cmk(self):
        """Test when a prompt is not encrypted with a customer-managed KMS key."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_encrypted_with_cmk.bedrock_prompt_encrypted_with_cmk import (
                bedrock_prompt_encrypted_with_cmk,
            )

            check = bedrock_prompt_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt {PROMPT_NAME} is not encrypted with a customer-managed KMS key."
            )
            assert result[0].resource_id == PROMPT_ID
            assert result[0].resource_arn == PROMPT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
