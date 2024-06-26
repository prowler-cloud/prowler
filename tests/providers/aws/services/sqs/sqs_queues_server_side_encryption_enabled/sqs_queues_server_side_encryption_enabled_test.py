from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sqs.sqs_service import Queue
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

test_kms_key_id = str(uuid4())
test_queue_name = str(uuid4())
test_queue_url = f"https://sqs.{AWS_REGION_EU_WEST_1}.amazonaws.com/{AWS_ACCOUNT_NUMBER}/{test_queue_name}"
test_queue_arn = (
    f"arn:aws:sqs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{test_queue_name}"
)


class Test_sqs_queues_server_side_encryption_enabled:
    def test_no_queues(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_server_side_encryption_enabled.sqs_queues_server_side_encryption_enabled import (
                sqs_queues_server_side_encryption_enabled,
            )

            check = sqs_queues_server_side_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_queues_with_encryption(self):
        sqs_client = mock.MagicMock
        sqs_client.queues = []
        sqs_client.queues.append(
            Queue(
                id=test_queue_url,
                name=test_queue_name,
                region=AWS_REGION_EU_WEST_1,
                kms_key_id=test_kms_key_id,
                arn=test_queue_arn,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_server_side_encryption_enabled.sqs_queues_server_side_encryption_enabled import (
                sqs_queues_server_side_encryption_enabled,
            )

            check = sqs_queues_server_side_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} is using Server Side Encryption."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn

    def test_queues_no_encryption(self):
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
        with mock.patch(
            "prowler.providers.aws.services.sqs.sqs_service.SQS",
            sqs_client,
        ):
            from prowler.providers.aws.services.sqs.sqs_queues_server_side_encryption_enabled.sqs_queues_server_side_encryption_enabled import (
                sqs_queues_server_side_encryption_enabled,
            )

            check = sqs_queues_server_side_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQS queue {test_queue_url} is not using Server Side Encryption."
            )
            assert result[0].resource_id == test_queue_url
            assert result[0].resource_arn == test_queue_arn
