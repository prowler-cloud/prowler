from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


class Test_rds_instance__no_event_subscriptions:
    @mock_aws
    def test_rds_no_events(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_event_subscriptions.rds_instance_event_subscriptions.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_event_subscriptions.rds_instance_event_subscriptions import (
                    rds_instance_event_subscriptions,
                )

                check = rds_instance_event_subscriptions()
                result = check.execute()

                assert len(result) == 1

    @mock_aws
    def test_rds_security_event_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-security-group",
            Enabled=True,
            Tags=[
                {"Key": "test", "Value": "testing"},
            ],
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_event_subscriptions.rds_instance_event_subscriptions.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_event_subscriptions.rds_instance_event_subscriptions import (
                    rds_instance_event_subscriptions,
                )

                check = rds_instance_event_subscriptions()
                result = check.execute()

                assert len(result) == 2
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS parameter group change events are not subscribed."
                )
                # assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                # assert (
                #    result[0].resource_arn
                #    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                # )
                # assert result[0].resource_tags == []
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == "RDS parameter group change events are not subscribed."
                )
                # assert result[0].resource_id == "db-master-1"
                assert result[1].region == AWS_REGION_US_EAST_1
                # assert (
                #    result[0].resource_arn
                #    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                # )
                # assert result[0].resource_tags == []
