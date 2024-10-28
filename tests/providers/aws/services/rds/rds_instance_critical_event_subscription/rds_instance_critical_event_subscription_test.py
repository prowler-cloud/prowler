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
RDS_ACCOUNT_ARN = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"


class Test_rds_instance_critical_event_subscription:
    @mock_aws
    def test_rds_no_events(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event categories of maintenance, configuration change, and failure are not subscribed."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == RDS_ACCOUNT_ARN
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_no_events_ignoring(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._scan_unused_services = False

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_event_subscription_enabled(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
            EventCategories=["maintenance", "configuration change", "failure"],
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
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended == "RDS instance events are subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "testing"}]

    @mock_aws
    def test_rds_instance_event_failure_only_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
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
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event categories of maintenance and configuration change are not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "testing"}]

    @mock_aws
    def test_rds_instance_event_maintenance_only_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
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
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event categories of configuration change and failure are not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_event_configuration_change_only_subscription(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
            EventCategories=["configuration change"],
            Enabled=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event categories of maintenance and failure are not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_event_configuration_change_and_maintenance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
            EventCategories=["maintenance", "configuration change"],
            Enabled=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event category of failure is not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_event_configuration_change_and_failure(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
            EventCategories=["configuration change", "failure"],
            Enabled=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event category of maintenance is not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_event_failure_and_maintenance(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.aurora-postgresql14",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="aurora-postgresql",
            DBName="aurora-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
            DBClusterIdentifier="db-cluster-1",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-instance",
            EventCategories=["failure", "maintenance"],
            Enabled=True,
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_critical_event_subscription.rds_instance_critical_event_subscription import (
                    rds_instance_critical_event_subscription,
                )

                check = rds_instance_critical_event_subscription()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS instance event category of configuration change is not subscribed."
                )
                assert result[0].resource_id == "TestSub"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:es:TestSub"
                )
                assert result[0].resource_tags == []
