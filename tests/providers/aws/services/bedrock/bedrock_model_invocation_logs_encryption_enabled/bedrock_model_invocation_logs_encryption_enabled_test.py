from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_bedrock_model_invocation_logs_encryption_enabled:
    @mock_aws
    def test_no_logging(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_s3_and_cloudwatch_logging_not_encrypted(self):
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="Test")
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="testconfigbucket")
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
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are not encrypted in S3 bucket: testconfigbucket and CloudWatch Log Group: Test."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_s3_logging_not_encrypted(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="testconfigbucket")
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are not encrypted in S3 bucket: testconfigbucket."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_cloudwatch_logging_not_encrypted(self):
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="Test")
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):

            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are not encrypted in CloudWatch Log Group: Test."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_s3_and_cloudwatch_logging_encrypted(self):
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="Test", kmsKeyId="testkey")
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="testconfigbucket")
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }

        s3_client.put_bucket_encryption(
            Bucket="testconfigbucket", ServerSideEncryptionConfiguration=sse_config
        )
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
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are encrypted."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_s3_logging_encrypted(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client.create_bucket(Bucket="testconfigbucket")
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }

        s3_client.put_bucket_encryption(
            Bucket="testconfigbucket", ServerSideEncryptionConfiguration=sse_config
        )
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are encrypted."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_cloudwatch_logging_encrypted(self):
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        logs_client.create_log_group(logGroupName="Test", kmsKeyId="testkey")
        bedrock = client("bedrock", region_name=AWS_REGION_US_EAST_1)

        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
            },
        }
        bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)

        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.bedrock_client",
            new=Bedrock(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.logs_client",
            new=Logs(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled.s3_client",
            new=S3(aws_provider),
        ):

            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logs_encryption_enabled.bedrock_model_invocation_logs_encryption_enabled import (
                bedrock_model_invocation_logs_encryption_enabled,
            )

            check = bedrock_model_invocation_logs_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Model Invocation logs are encrypted."
            )
            assert result[0].resource_id == "model-invocation-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:bedrock:us-east-1:123456789012:model-invocation-logging"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
