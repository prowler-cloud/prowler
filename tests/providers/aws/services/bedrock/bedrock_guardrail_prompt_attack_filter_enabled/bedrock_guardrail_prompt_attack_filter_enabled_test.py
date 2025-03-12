from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

GUARDRAIL_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id"
)


def mock_make_api_call_high_filter(self, operation_name, kwarg):
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test",
                }
            ]
        }
    elif operation_name == "GetGuardrail":
        return {
            "name": "test",
            "guardrailId": "test-id",
            "guardrailArn": GUARDRAIL_ARN,
            "status": "READY",
            "contentPolicy": {
                "filters": [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputStrength": "HIGH",
                        "outputStrength": "NONE",
                    },
                ]
            },
            "blockedInputMessaging": "Sorry, the model cannot answer this question.",
            "blockedOutputsMessaging": "Sorry, the model cannot answer this question.",
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_no_filter(self, operation_name, kwarg):
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test",
                }
            ]
        }
    elif operation_name == "GetGuardrail":
        return {
            "name": "test",
            "guardrailId": "test-id",
            "guardrailArn": GUARDRAIL_ARN,
            "status": "READY",
            "contentPolicy": {"filters": []},
            "blockedInputMessaging": "Sorry, the model cannot answer this question.",
            "blockedOutputsMessaging": "Sorry, the model cannot answer this question.",
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_low_filter(self, operation_name, kwarg):
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test",
                }
            ]
        }
    elif operation_name == "GetGuardrail":
        return {
            "name": "test",
            "guardrailId": "test-id",
            "guardrailArn": GUARDRAIL_ARN,
            "status": "READY",
            "contentPolicy": {
                "filters": [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputStrength": "LOW",
                        "outputStrength": "NONE",
                    },
                ]
            },
            "blockedInputMessaging": "Sorry, the model cannot answer this question.",
            "blockedOutputsMessaging": "Sorry, the model cannot answer this question.",
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_guardrail_prompt_attack_filter_enabled:
    @mock_aws
    def test_no_guardrails(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled import (
                bedrock_guardrail_prompt_attack_filter_enabled,
            )

            check = bedrock_guardrail_prompt_attack_filter_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_high_filter
    )
    @mock_aws
    def test_guardrail_high_filter(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled import (
                bedrock_guardrail_prompt_attack_filter_enabled,
            )

            check = bedrock_guardrail_prompt_attack_filter_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Guardrail test is configured to detect and block prompt attacks with a HIGH strength."
            )
            assert result[0].resource_id == "test-id"
            assert result[0].resource_arn == GUARDRAIL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_no_filter
    )
    @mock_aws
    def test_guardrail_no_filter(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled import (
                bedrock_guardrail_prompt_attack_filter_enabled,
            )

            check = bedrock_guardrail_prompt_attack_filter_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Guardrail test is not configured to block prompt attacks."
            )
            assert result[0].resource_id == "test-id"
            assert result[0].resource_arn == GUARDRAIL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_low_filter
    )
    @mock_aws
    def test_guardrail_low_filter(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrail_prompt_attack_filter_enabled.bedrock_guardrail_prompt_attack_filter_enabled import (
                bedrock_guardrail_prompt_attack_filter_enabled,
            )

            check = bedrock_guardrail_prompt_attack_filter_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Guardrail test is configured to block prompt attacks but with a filter strength of LOW, not HIGH."
            )
            assert result[0].resource_id == "test-id"
            assert result[0].resource_arn == GUARDRAIL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
