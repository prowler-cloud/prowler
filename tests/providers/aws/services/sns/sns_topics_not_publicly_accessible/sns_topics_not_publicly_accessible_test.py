from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sns.sns_service import Topic
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

kms_key_id = str(uuid4())
topic_name = "test-topic"
topic_arn = f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}"
test_policy_restricted = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"{AWS_ACCOUNT_NUMBER}"},
            "Action": ["sns:Publish"],
            "Resource": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
        }
    ]
}

test_policy_restricted_condition = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["sns:Publish"],
            "Resource": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
            "Condition": {"StringEquals": {"aws:SourceAccount": AWS_ACCOUNT_NUMBER}},
        }
    ]
}

test_policy_restricted_default_condition = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["sns:Publish"],
            "Resource": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
            "Condition": {"StringEquals": {"aws:SourceOwner": AWS_ACCOUNT_NUMBER}},
        }
    ]
}

test_policy_not_restricted = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["sns:Publish"],
            "Resource": f"arn:aws:sns:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
        }
    ]
}


class Test_sns_topics_not_publicly_accessible:
    def test_no_topics(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_topic_not_public(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                policy=test_policy_restricted,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SNS topic {topic_name} is not publicly accesible."
            )
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_topic_no_policy(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        sns_client.topics.append(
            Topic(arn=topic_arn, name=topic_name, region=AWS_REGION_EU_WEST_1)
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SNS topic {topic_name} is not publicly accesible."
            )
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_topic_public_with_condition(self):
        sns_client = mock.MagicMock
        sns_client.audited_account = AWS_ACCOUNT_NUMBER
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                policy=test_policy_restricted_condition,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SNS topic {topic_name} is not public because its policy only allows access from the same account."
            )
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_topic_public_with_default_condition(self):
        sns_client = mock.MagicMock
        sns_client.audited_account = AWS_ACCOUNT_NUMBER
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                policy=test_policy_restricted_default_condition,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SNS topic {topic_name} is not public because its policy only allows access from the same account."
            )
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_topic_public(self):
        sns_client = mock.MagicMock
        sns_client.topics = []
        sns_client.topics.append(
            Topic(
                arn=topic_arn,
                name=topic_name,
                region=AWS_REGION_EU_WEST_1,
                policy=test_policy_not_restricted,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sns.sns_service.SNS",
            sns_client,
        ):
            from prowler.providers.aws.services.sns.sns_topics_not_publicly_accessible.sns_topics_not_publicly_accessible import (
                sns_topics_not_publicly_accessible,
            )

            check = sns_topics_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SNS topic {topic_name} is public because its policy allows public access."
            )
            assert result[0].resource_id == topic_name
            assert result[0].resource_arn == topic_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
