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


def mock_make_api_call_without_guardrails(self, operation_name, kwarg):
    """Mock API call returning no guardrails."""
    if operation_name == "ListGuardrails":
        return {"guardrails": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_guardrails_only_in_us_east_1(self, operation_name, kwarg):
    """Mock API call returning a guardrail only in us-east-1 and none elsewhere."""
    if operation_name == "ListGuardrails":
        if self.meta.region_name == AWS_REGION_US_EAST_1:
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
        return {"guardrails": []}
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


def mock_make_api_call_guardrail_validation_exception(self, operation_name, kwarg):
    """Mock API call raising ValidationException for ListGuardrails."""
    if operation_name == "ListGuardrails":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Guardrails are not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_guardrails_configured:
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_without_guardrails,
    )
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
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured import (
                bedrock_guardrails_configured,
            )

            check = bedrock_guardrails_configured()
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
                == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrails"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_without_guardrails,
    )
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
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured import (
                bedrock_guardrails_configured,
            )

            check = bedrock_guardrails_configured()
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
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured import (
                bedrock_guardrails_configured,
            )

            check = bedrock_guardrails_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock guardrail test-guardrail is available in region {AWS_REGION_US_EAST_1}. This does not confirm that the guardrail is attached to agents or used on model invocations."
            )
            assert result[0].resource_id == "test-id"
            assert result[0].resource_arn == GUARDRAIL_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_guardrails_only_in_us_east_1,
    )
    @mock_aws
    def test_guardrails_in_one_region_only(self):
        """Test PASS in the region with a guardrail and FAIL in the region without one."""
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
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured import (
                bedrock_guardrails_configured,
            )

            check = bedrock_guardrails_configured()
            result = check.execute()

            assert len(result) == 2

            results_by_region = {r.region: r for r in result}

            eu_result = results_by_region[AWS_REGION_EU_WEST_1]
            assert eu_result.status == "FAIL"
            assert (
                eu_result.status_extended
                == f"Bedrock has no guardrails configured in region {AWS_REGION_EU_WEST_1}."
            )
            assert eu_result.resource_id == "bedrock-guardrails"
            assert (
                eu_result.resource_arn
                == f"arn:aws:bedrock:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:guardrails"
            )
            assert eu_result.resource_tags == []

            us_result = results_by_region[AWS_REGION_US_EAST_1]
            assert us_result.status == "PASS"
            assert (
                us_result.status_extended
                == f"Bedrock guardrail test-guardrail is available in region {AWS_REGION_US_EAST_1}. This does not confirm that the guardrail is attached to agents or used on model invocations."
            )
            assert us_result.resource_id == "test-id"
            assert us_result.resource_arn == GUARDRAIL_ARN
            assert us_result.resource_tags == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_guardrail_validation_exception,
    )
    @mock_aws
    def test_guardrails_unsupported_region_is_skipped(self):
        """Test unsupported regions are skipped instead of failing."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_guardrails_configured.bedrock_guardrails_configured import (
                bedrock_guardrails_configured,
            )

            check = bedrock_guardrails_configured()
            result = check.execute()

            assert len(result) == 0
