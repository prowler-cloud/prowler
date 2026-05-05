from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

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


def mock_make_api_call_list_prompts_access_denied(self, operation_name, kwarg):
    """Mock API call where ListPrompts fails with AccessDeniedException."""
    if operation_name == "ListPrompts":
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform: bedrock:ListPrompts",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_with_prompts(self, operation_name, kwarg):
    """Mock API call that returns prompts."""
    if operation_name == "ListPrompts":
        return {
            "promptSummaries": [
                {
                    "id": "test-prompt-id",
                    "name": "test-prompt",
                    "arn": PROMPT_ARN,
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_with_multiple_prompts(self, operation_name, kwarg):
    """Mock API call that returns multiple prompts."""
    if operation_name == "ListPrompts":
        return {
            "promptSummaries": [
                {
                    "id": "test-prompt-id-1",
                    "name": "test-prompt-1",
                    "arn": f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/test-prompt-id-1",
                },
                {
                    "id": "test-prompt-id-2",
                    "name": "test-prompt-2",
                    "arn": f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/test-prompt-id-2",
                },
                {
                    "id": "test-prompt-id-3",
                    "name": "test-prompt-3",
                    "arn": f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/test-prompt-id-3",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_no_prompts(self, operation_name, kwarg):
    """Mock API call that returns no prompts."""
    if operation_name == "ListPrompts":
        return {"promptSummaries": []}
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_prompt_management_exists:
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_prompts,
    )
    @mock_aws
    def test_no_prompts(self):
        """Test FAIL when no prompts exist in the region."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists import (
                bedrock_prompt_management_exists,
            )

            check = bedrock_prompt_management_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No Bedrock Prompt Management prompts exist in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == "prompt-management"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt-management"
            )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_with_prompts,
    )
    @mock_aws
    def test_prompts_exist(self):
        """Test PASS when prompts exist in the region."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists import (
                bedrock_prompt_management_exists,
            )

            check = bedrock_prompt_management_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock Prompt Management prompt test-prompt exists in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == "test-prompt-id"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == PROMPT_ARN

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_with_multiple_prompts,
    )
    @mock_aws
    def test_multiple_prompts_exist(self):
        """Test PASS with one finding per prompt when multiple prompts exist."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists import (
                bedrock_prompt_management_exists,
            )

            check = bedrock_prompt_management_exists()
            result = check.execute()

            assert len(result) == 3
            for index, finding in enumerate(result, start=1):
                expected_name = f"test-prompt-{index}"
                expected_id = f"test-prompt-id-{index}"
                assert finding.status == "PASS"
                assert (
                    finding.status_extended
                    == f"Bedrock Prompt Management prompt {expected_name} exists in region {AWS_REGION_US_EAST_1}."
                )
                assert finding.resource_id == expected_id
                assert finding.region == AWS_REGION_US_EAST_1
                assert (
                    finding.resource_arn
                    == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/{expected_id}"
                )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_no_prompts,
    )
    @mock_aws
    def test_no_prompts_multiple_regions(self):
        """Test FAIL in multiple regions when no prompts exist."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists import (
                bedrock_prompt_management_exists,
            )

            check = bedrock_prompt_management_exists()
            result = check.execute()

            assert len(result) == 2
            for finding in result:
                assert finding.status == "FAIL"
                assert (
                    finding.status_extended
                    == f"No Bedrock Prompt Management prompts exist in region {finding.region}."
                )
                assert finding.resource_id == "prompt-management"
                assert (
                    finding.resource_arn
                    == f"arn:aws:bedrock:{finding.region}:{AWS_ACCOUNT_NUMBER}:prompt-management"
                )
            regions = {finding.region for finding in result}
            assert regions == {AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1}

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_prompts_access_denied,
    )
    @mock_aws
    def test_list_prompts_client_error_skips_region(self):
        """Test that regions where ListPrompts fails produce no findings."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_prompt_management_exists.bedrock_prompt_management_exists import (
                bedrock_prompt_management_exists,
            )

            check = bedrock_prompt_management_exists()
            result = check.execute()

            assert result == []
