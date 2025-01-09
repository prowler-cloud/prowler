from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_event_notifications_enabled:
    # No Buckets
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled import (
                    s3_bucket_event_notifications_enabled,
                )

                check = s3_bucket_event_notifications_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_event_notifications_disabled(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled import (
                    s3_bucket_event_notifications_enabled,
                )

                check = s3_bucket_event_notifications_enabled()
                result = check.execute()

                assert len(result) == 1

                # US-EAST-1 Source Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} does not have event notifications enabled."
                )
                assert result[0].resource_id == bucket_name
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_event_notifications_enabled(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {
                        "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ],
                "QueueConfigurations": [
                    {
                        "QueueArn": "arn:aws:sqs:us-east-1:123456789012:my-queue",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ],
                "TopicConfigurations": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:my-topic",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_event_notifications_enabled.s3_bucket_event_notifications_enabled import (
                    s3_bucket_event_notifications_enabled,
                )

                check = s3_bucket_event_notifications_enabled()
                result = check.execute()

                assert len(result) == 1

                # US-EAST-1 Source Bucket
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} does have event notifications enabled."
                )
                assert result[0].resource_id == bucket_name
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
