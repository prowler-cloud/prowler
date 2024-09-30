from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

RDS_ACCOUNT_ARN = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"


class Test_rds_cluster_critical_event_subscription:
    @mock_aws
    def test_rds_no_events(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription import (
                    rds_cluster_critical_event_subscription,
                )

                check = rds_cluster_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS cluster event categories of maintenance and failure are not subscribed."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == RDS_ACCOUNT_ARN
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_cluster_event_subscription_enabled(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="password",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-cluster",
            Enabled=True,
            EventCategories=["maintenance", "failure"],
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
                "prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription import (
                    rds_cluster_critical_event_subscription,
                )

                check = rds_cluster_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].status_extended == "RDS cluster events are subscribed."
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "testing"}]

    @mock_aws
    def test_rds_cluster_event_failure_only_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="password",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-cluster",
            EventCategories=["failure"],
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
                "prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription import (
                    rds_cluster_critical_event_subscription,
                )

                check = rds_cluster_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS cluster event category of maintenance is not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "testing"}]

    @mock_aws
    def test_rds_cluster_event_maintenance_only_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-cluster-1",
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="password",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-cluster",
            EventCategories=["maintenance"],
            Enabled=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_cluster_critical_event_subscription.rds_cluster_critical_event_subscription import (
                    rds_cluster_critical_event_subscription,
                )

                check = rds_cluster_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS cluster event category of failure is not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []
