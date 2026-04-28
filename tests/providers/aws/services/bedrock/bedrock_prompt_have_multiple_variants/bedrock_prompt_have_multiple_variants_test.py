from unittest import mock

import botocore

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

PROMPT_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/test-prompt-id"
PROMPT_ID = "test-prompt-id"
PROMPT_NAME = "test-prompt"


def mock_make_api_call_single_variant(self, operation_name, kwarg):
    """Mock API call returning a prompt with a single variant."""
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
            "variants": [
                {
                    "name": "variant-1",
                    "modelId": "anthropic.claude-v2",
                    "templateType": "TEXT",
                }
            ],
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_multiple_variants(self, operation_name, kwarg):
    """Mock API call returning a prompt with multiple variants."""
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
            "variants": [
                {
                    "name": "variant-1",
                    "modelId": "anthropic.claude-v2",
                    "templateType": "TEXT",
                },
                {
                    "name": "variant-2",
                    "modelId": "anthropic.claude-3-sonnet",
                    "templateType": "TEXT",
                },
            ],
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_no_variants(self, operation_name, kwarg):
    """Mock API call returning a prompt with no variants."""
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
            "variants": [],
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_prompt_have_multiple_variants:
    """Test suite for the bedrock_prompt_have_multiple_variants check."""

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
                "prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants import (
                bedrock_prompt_have_multiple_variants,
            )

            check = bedrock_prompt_have_multiple_variants()
            result = check.execute()

            assert len(result) == 0

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_single_variant,
    )
    def test_prompt_with_single_variant(self):
        """Test when a prompt has only one variant configured."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants import (
                bedrock_prompt_have_multiple_variants,
            )

            check = bedrock_prompt_have_multiple_variants()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt {PROMPT_NAME} has only 1 variant configured, multiple variants are recommended for A/B testing and resilience."
            )
            assert result[0].resource_id == PROMPT_ID
            assert result[0].resource_arn == PROMPT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_multiple_variants,
    )
    def test_prompt_with_multiple_variants(self):
        """Test when a prompt has multiple variants configured."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants import (
                bedrock_prompt_have_multiple_variants,
            )

            check = bedrock_prompt_have_multiple_variants()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt {PROMPT_NAME} has 2 variants configured for A/B testing and resilience."
            )
            assert result[0].resource_id == PROMPT_ID
            assert result[0].resource_arn == PROMPT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_variants,
    )
    def test_prompt_with_no_variants(self):
        """Test when a prompt has no variants configured."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_have_multiple_variants.bedrock_prompt_have_multiple_variants import (
                bedrock_prompt_have_multiple_variants,
            )

            check = bedrock_prompt_have_multiple_variants()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt {PROMPT_NAME} has only 0 variants configured, multiple variants are recommended for A/B testing and resilience."
            )
            assert result[0].resource_id == PROMPT_ID
            assert result[0].resource_arn == PROMPT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
