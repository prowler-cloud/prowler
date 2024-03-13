from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sns.sns_service import Topic
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

kms_key_id = str(uuid4())
topic_name = "test-topic"
topic_arn = f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}"


class Test_sns_topics_kms_encryption_at_rest_enabled:
    def test_no_topics(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_kms_encryption_at_rest_enabled.sns_topics_kms_encryption_at_rest_enabled import (
                sns_topics_kms_encryption_at_rest_enabled,
            )

            check = sns_topics_kms_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_topics_with_key(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                kms_master_key_id=kms_key_id,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_kms_encryption_at_rest_enabled.sns_topics_kms_encryption_at_rest_enabled import (
                sns_topics_kms_encryption_at_rest_enabled,
            )

            check = sns_topics_kms_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("is encrypted", result[0].status_extended)
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn

    def test_topics_no_key(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        sns_client.topics.append(
            Topic(arn=topic_arn, name=topic_name, region=AWS_REGION_EU_WEST_1)
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_kms_encryption_at_rest_enabled.sns_topics_kms_encryption_at_rest_enabled import (
                sns_topics_kms_encryption_at_rest_enabled,
            )

            check = sns_topics_kms_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("is not encrypted", result[0].status_extended)
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
