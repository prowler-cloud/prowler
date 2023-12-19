from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sqs.sqs_service import Queue
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

test_queue_name = str(uuid4())
test_queue_url = f"https://sqs.{AWS_REGION_EU_WEST_1}.amazonaws.com/{AWS_ACCOUNT_NUMBER}/{test_queue_name}"
test_queue_arn = (
    f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{test_queue_name}"
)

test_restricted_policy = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": {"AWS": {AWS_ACCOUNT_NUMBER}},
            "Action": "sqs:ReceiveMessage",
            "Resource": test_queue_arn,
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
            "Resource": test_queue_arn,
        }
    ],
}

test_public_policy_with_condition_same_account_not_valid = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": test_queue_arn,
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "2009-01-31T12:00Z"},
                "DateLessThan": {"aws:CurrentTime": "2009-01-31T15:00Z"},
            },
        }
    ],
}

test_public_policy_with_condition_same_account = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": test_queue_arn,
            "Condition": {
                "StringEquals": {"aws:SourceAccount": f"{AWS_ACCOUNT_NUMBER}"}
            },
        }
    ],
}

test_public_policy_with_condition_diff_account = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": test_queue_arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": "111122223333"}},
        }
    ],
}

test_public_policy_with_invalid_condition_block = {
    "Version": "2012-10-17",
    "Id": "Queue1_Policy_UUID",
    "Statement": [
        {
            "Sid": "Queue1_AnonymousAccess_ReceiveMessage",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs:ReceiveMessage",
            "Resource": test_queue_arn,
            "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2009-01-31T12:00Z"}},
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
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_restricted_policy,
                arn=test_queue_arn,
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
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_queues_public(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy,
                arn=test_queue_arn,
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
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_queues_public_with_condition_not_valid(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_same_account_not_valid,
                arn=test_queue_arn,
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
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_queues_public_with_condition_valid(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_same_account,
                arn=test_queue_arn,
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
                == f"SQS queue {test_queue_url} is not public because its policy only allows access from the same account."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_queues_public_with_condition_valid_with_other_account(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_condition_diff_account,
                arn=test_queue_arn,
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
                == f"SQS queue {test_queue_url} is not public because its policy only allows access from the same account."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_queues_public_with_condition_with_invalid_block(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.audited_account = AWS_ACCOUNT_NUMBER
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_public_policy_with_invalid_condition_block,
                arn=test_queue_arn,
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
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} is public because its policy allows public access, and the condition does not limit access to resources within the same account."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
