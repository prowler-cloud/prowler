from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_sqs_queues_not_publicly_accessible_fixer:
    @mock_aws
    def test_queue_public(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)

        queue_url = sqs_client.create_queue(QueueName="test-queue")["QueueUrl"]

        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]})
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.sqs.sqs_service import SQS

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer.sqs_client",
                new=SQS(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(queue_url, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_queue_public_with_aws(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)

        queue_url = sqs_client.create_queue(QueueName="test-queue")["QueueUrl"]

        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": dumps(
                    {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]}
                )
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.sqs.sqs_service import SQS

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer.sqs_client",
                new=SQS(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(queue_url, AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_queue_public_error(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)

        queue_url = sqs_client.create_queue(QueueName="test-queue")["QueueUrl"]

        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": dumps(
                    {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]}
                )
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.sqs.sqs_service import SQS

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer.sqs_client",
                new=SQS(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible_fixer import (
                fixer,
            )

            assert not fixer("queue_url_non_existing", AWS_REGION_EU_WEST_1)
