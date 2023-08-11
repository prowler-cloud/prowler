from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sqs.sqs_service import Queue

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

queue_id = str(uuid4())
topic_arn = f"arn:aws:sqs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:{queue_id}"

test_restricted_policy = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": {"AWS": {AWS_ACCOUNT_NUMBER}},
            "Action": "sqs:ReceiveMessage",
            "Resource": topic_arn,
        }
    ],
}

test_public_policy = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": topic_arn,
        }
    ],
}

test_public_policy_with_condition_not_valid = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": topic_arn,
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "2009-01-31T12:00Z"},
                "DateLessThan": {"aws:CurrentTime": "2009-01-31T15:00Z"},
            },
        }
    ],
}

test_public_policy_with_condition = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": topic_arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        }
    ],
}


class Test_sqs_queues_not_publicly_accessible:
    def test_no_queues(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import (
                sqs_queues_not_publicly_accessible,
            )

            check = sqs_queues_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_queues_not_public(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=queue_id,
                region=AWS_REGION,
                policy=test_restricted_policy,
                arn="arn_test",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import (
                sqs_queues_not_publicly_accessible,
            )

            check = sqs_queues_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("is not public", result[0].status_extended)
            assert result[0].resource_id == queue_id
            assert result[0].resource_arn == "arn_test"

    def test_queues_public(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=queue_id,
                region=AWS_REGION,
                policy=test_public_policy,
                arn="arn_test",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import (
                sqs_queues_not_publicly_accessible,
            )

            check = sqs_queues_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is public because its policy allows public access",
                result[0].status_extended,
            )
            assert result[0].resource_id == queue_id
            assert result[0].resource_arn == "arn_test"

    def test_queues_public_with_condition_not_valid(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=queue_id,
                region=AWS_REGION,
                policy=test_public_policy_with_condition_not_valid,
                arn="arn_test",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import (
                sqs_queues_not_publicly_accessible,
            )

            check = sqs_queues_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is public because its policy allows public access",
                result[0].status_extended,
            )
            assert result[0].resource_id == queue_id
            assert result[0].resource_arn == "arn_test"

    def test_queues_public_with_condition_valid(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=queue_id,
                region=AWS_REGION,
                policy=test_public_policy_with_condition,
                arn="arn_test",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_not_publicly_accessible.sqs_queues_not_publicly_accessible import (
                sqs_queues_not_publicly_accessible,
            )

            check = sqs_queues_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQS queue {queue_id} is not public because its policy only allows access from the same account."
            )
            assert result[0].resource_id == queue_id
            assert result[0].resource_arn == "arn_test"
