from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_bedrock_model_invocation_logging_enabled:
    @mock_aws
    def test_no_loggings(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled import (
                bedrock_model_invocation_logging_enabled,
            )

            check = bedrock_model_invocation_logging_enabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation Logging is disabled."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == f"arn:aws:bedrock:{result[0].region}:123456789012:model-invocation-logging"
            )
            assert result[0].resource_tags == []
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Bedrock Model Invocation Logging is disabled."
            )
            assert result[1].resource_id == "model-invocation-logging"
            assert (
                result[1].resource_arn
                == f"arn:aws:bedrock:{result[1].region}:123456789012:model-invocation-logging"
            )
            assert result[1].resource_tags == []

    @mock_aws
    def test_s3_and_cloudwatch_logging(self):
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
                "largeDataDeliveryS3Config": {
                    "bucketName": "testbucket",
                },
            },
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled import (
                bedrock_model_invocation_logging_enabled,
            )

            check = bedrock_model_invocation_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation Logging is enabled in CloudWatch Log Group: Test and S3 Bucket: testconfigbucket."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_s3_logging(self):
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled import (
                bedrock_model_invocation_logging_enabled,
            )

            check = bedrock_model_invocation_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation Logging is enabled in S3 Bucket: testconfigbucket."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_cloudwatch_logging(self):
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_enabled.bedrock_model_invocation_logging_enabled import (
                bedrock_model_invocation_logging_enabled,
            )

            check = bedrock_model_invocation_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation Logging is enabled in CloudWatch Log Group: Test."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
