from json import dumps, loads
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


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

    @mock_aws
    def test_queue_public_keeps_non_public_statements(self):
        sqs_client = client("sqs", region_name=AWS_REGION_EU_WEST_1)

        queue_url = sqs_client.create_queue(QueueName="test-queue")["QueueUrl"]
        queue_arn = (
            f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:test-queue"
        )
        sns_statement = {
            "Sid": "AllowSNSTopic",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {
                "ArnEquals": {
                    "aws:SourceArn": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:test-topic"
                }
            },
        }
        deny_statement = {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "sqs:*",
            "Resource": queue_arn,
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }

        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "Policy": dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "PublicAccess",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sqs:SendMessage",
                                "Resource": queue_arn,
                            },
                            sns_statement,
                            deny_statement,
                        ],
                    }
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

        policy = loads(
            sqs_client.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["Policy"]
            )["Attributes"]["Policy"]
        )
        assert policy["Statement"] == [
            sns_statement,
            deny_statement,
            {
                "Sid": "ProwlerFixerStatement",
                "Effect": "Allow",
                "Principal": {"AWS": AWS_ACCOUNT_NUMBER},
                "Action": "sqs:*",
                "Resource": queue_arn,
            },
        ]
