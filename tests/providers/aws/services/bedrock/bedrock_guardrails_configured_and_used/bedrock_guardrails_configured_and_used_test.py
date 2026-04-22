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


def mock_make_api_call_with_guardrail(self, operation_name, kwarg):
    """Mock API call returning one guardrail in us-east-1."""
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test-guardrail",
                }
            ]
        }
    elif operation_name == "GetGuardrail":
        return {
            "name": "test-guardrail",
            "guardrailId": "test-id",
            "guardrailArn": GUARDRAIL_ARN,
            "status": "READY",
            "blockedInputMessaging": "Blocked",
            "blockedOutputsMessaging": "Blocked",
            "contentPolicy": {"filters": []},
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_guardrails_configured_and_used:
    @mock_aws
    def test_no_guardrails_single_region(self):
        """Test FAIL when no guardrails are configured in a single region."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used import (
                bedrock_guardrails_configured_and_used,
            )

            check = bedrock_guardrails_configured_and_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bedrock has no guardrails configured in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == "bedrock-guardrails"
            assert (
                result[0].resource_arn
                == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_no_guardrails_multi_region(self):
        """Test FAIL in both regions when no guardrails are configured."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used import (
                bedrock_guardrails_configured_and_used,
            )

            check = bedrock_guardrails_configured_and_used()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "bedrock-guardrails"
            assert result[0].resource_tags == []
            assert result[1].status == "FAIL"
            assert result[1].resource_id == "bedrock-guardrails"
            assert result[1].resource_tags == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_with_guardrail,
    )
    @mock_aws
    def test_guardrail_configured(self):
        """Test PASS when at least one guardrail is configured in the region."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured_and_used.bedrock_guardrails_configured_and_used import (
                bedrock_guardrails_configured_and_used,
            )

            check = bedrock_guardrails_configured_and_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock has 1 guardrail(s) configured in region {AWS_REGION_US_EAST_1}: test-guardrail."
            )
            assert result[0].resource_id == "bedrock-guardrails"
            assert (
                result[0].resource_arn
                == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
