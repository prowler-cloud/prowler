from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sqs.sqs_service import Queue
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

test_queue_name = str(uuid4())
test_queue_url = f"https://sqs.{AWS_REGION_EU_WEST_1}.amazonaws.com/{AWS_ACCOUNT_NUMBER}/{test_queue_name}"
test_queue_arn = (
    f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{test_queue_name}"
)


class Test_sqs_queues_secure_transport_enabled:
    def test_no_queues(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_queues_no_policy(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} does not have a policy, thus it allows HTTP requests."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn

    def test_queues_policy_statement_list_pass(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "sqs:*",
                            "Principal": "*",
                            "Resource": test_queue_arn,
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ],
                },
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} has a policy to deny requests over insecure transport."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn

    def test_queues_policy_statement_single_action_fail(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Deny",
                        "Action": "sqs:SendMessage",
                        "Principal": {"AWS": "*"},
                        "Resource": test_queue_arn,
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                },
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} allows requests over insecure transport in the policy."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn

    def test_queues_policy_statement_uppercase_secure_transport_key_pass(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "sqs:*",
                            "Principal": "*",
                            "Resource": test_queue_arn,
                            "Condition": {"Bool": {"AWS:SecureTransport": "false"}},
                        }
                    ],
                },
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} has a policy to deny requests over insecure transport."
            )

    def test_queues_policy_statement_complete_action_set_pass(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = [
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Deny",
                        "Action": [
                            "SQS:AddPermission",
                            "SQS:CancelMessageMoveTask",
                            "SQS:ChangeMessageVisibility",
                            "SQS:ChangeMessageVisibilityBatch",
                            "SQS:CreateQueue",
                            "SQS:DeleteMessage",
                            "SQS:DeleteMessageBatch",
                            "SQS:DeleteQueue",
                            "SQS:GetQueueAttributes",
                            "SQS:GetQueueUrl",
                            "SQS:ListDeadLetterSourceQueues",
                            "SQS:ListMessageMoveTasks",
                            "SQS:ListQueues",
                            "SQS:ListQueueTags",
                            "SQS:PurgeQueue",
                            "SQS:ReceiveMessage",
                            "SQS:RemovePermission",
                            "SQS:SendMessage",
                            "SQS:SendMessageBatch",
                            "SQS:SetQueueAttributes",
                            "SQS:StartMessageMoveTask",
                            "SQS:TagQueue",
                            "SQS:UntagQueue",
                        ],
                        "Principal": {"AWS": "*"},
                        "Resource": test_queue_arn,
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                },
            )
        ]
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} has a policy to deny requests over insecure transport."
            )

    def test_queues_policy_statement_scoped_principal_fail(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Deny",
                        "Action": "sqs:*",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/example"},
                        "Resource": test_queue_arn,
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                },
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_queues_policy_statement_single_object_fail(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                arn=test_queue_arn,
                policy={
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Allow",
                        "Action": "sqs:*",
                        "Resource": test_queue_arn,
                    },
                },
            )
        )
        with (
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_service.SQS",
                new=sqs_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sqs.sqs_client.sqs_client",
                new=sqs_client,
            ),
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_secure_transport_enabled.sqs_queues_secure_transport_enabled import (
                sqs_queues_secure_transport_enabled,
            )

            check = sqs_queues_secure_transport_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} allows requests over insecure transport in the policy."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
