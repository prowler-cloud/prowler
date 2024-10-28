from datetime import datetime
from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.rds.rds_service import RDS, Certificate, DBInstance
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_RDS_Service:
    # Test RDS Service
    @mock_aws
    def test_service(self):
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.service == "rds"

    # Test RDS Client
    @mock_aws
    def test_client(self):
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        for regional_client in rds.regional_clients.values():
            assert regional_client.__class__.__name__ == "RDS"

    # Test RDS Session
    @mock_aws
    def test__get_session__(self):
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.session.__class__.__name__ == "Session"

    # Test RDS Session
    @mock_aws
    def test_audited_account(self):
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.audited_account == AWS_ACCOUNT_NUMBER

    # Test RDS Describe DB Instances
    @mock_aws
    def test_describe_db_instances(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            EnableCloudwatchLogsExports=["audit", "error"],
            MultiAZ=True,
            DBParameterGroupName="test",
            DBClusterIdentifier="cluster-postgres",
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
            CopyTagsToSnapshot=True,
            Port=5432,
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_instances) == 1
        db_instance_arn, db_instance = next(iter(rds.db_instances.items()))
        assert db_instance.id == "db-master-1"
        assert db_instance.region == AWS_REGION_US_EAST_1
        assert (
            db_instance.endpoint["Address"]
            == "db-master-1.aaaaaaaaaa.us-east-1.rds.amazonaws.com"
        )
        assert db_instance.status == "available"
        assert db_instance.public
        assert db_instance.encrypted
        assert db_instance.backup_retention_period == 10
        assert db_instance.cloudwatch_logs == ["audit", "error"]
        assert db_instance.deletion_protection
        assert db_instance.auto_minor_version_upgrade
        assert db_instance.multi_az
        assert db_instance.cluster_id
        assert db_instance.tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert "test" in db_instance.parameter_groups
        assert db_instance.subnet_ids == []
        assert db_instance.copy_tags_to_snapshot
        assert db_instance.port == 5432

    @mock_aws
    def test_describe_db_parameters(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            DBParameterGroupName="test",
        )

        conn.modify_db_parameter_group(
            DBParameterGroupName="test",
            Parameters=[
                {
                    "ParameterName": "rds.force_ssl",
                    "ParameterValue": "1",
                    "ApplyMethod": "immediate",
                },
            ],
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_instances) == 1
        db_instance_arn, db_instance = next(iter(rds.db_instances.items()))
        assert db_instance.id == "db-master-1"
        assert db_instance.region == AWS_REGION_US_EAST_1
        for parameter in db_instance.parameters:
            if parameter["ParameterName"] == "rds.force_ssl":
                assert parameter["ParameterValue"] == "1"

    @mock_aws
    def test_describe_db_certificate(self):
        rds_client = mock.MagicMock
        rds_client.db_instances = {
            "arn:aws:rds:us-east-1:123456789012:db:db-master-1": DBInstance(
                id="db-master-1",
                region=AWS_REGION_US_EAST_1,
                endpoint={
                    "Address": "db-master-1.aaaaaaaaaa.us-east-1.rds.amazonaws.com",
                    "Port": 5432,
                },
                status="available",
                public=True,
                encrypted=True,
                backup_retention_period=10,
                cloudwatch_logs=["audit", "error"],
                deletion_protection=True,
                auto_minor_version_upgrade=True,
                multi_az=True,
                cluster_id="cluster-postgres",
                tags=[{"Key": "test", "Value": "test"}],
                parameter_groups=["test"],
                copy_tags_to_snapshot=True,
                ca_cert="rds-cert-2015",
                arn="arn:aws:rds:us-east-1:123456789012:db:db-master-1",
                engine="postgres",
                engine_version="9.6.9",
                username="test",
                iam_auth=False,
                cert=[
                    Certificate(
                        id="rds-cert-2015",
                        arn="arn:aws:rds:us-east-1:123456789012:cert:rds-cert-2015",
                        region=AWS_REGION_US_EAST_1,
                        type="CA",
                        valid_from=datetime(2015, 1, 1),
                        valid_till=datetime(2025, 1, 1),
                        customer_override=False,
                        customer_override_valid_till=datetime(2025, 1, 1),
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_service import RDS

            rds = RDS(rds_client)
            assert len(rds.db_instances) == 1
            db_instance_arn, db_instance = next(iter(rds.db_instances.items()))
            assert db_instance.id == "db-master-1"
            assert db_instance.region == AWS_REGION_US_EAST_1
            assert len(db_instance.cert) == 1
            for cert in db_instance.cert:
                assert cert.id == "rds-cert-2015"
                assert cert.type == "CA"
                assert cert.valid_from == datetime(2015, 1, 1)
                assert cert.valid_till == datetime(2025, 1, 1)
                assert not cert.customer_override
                assert cert.customer_override_valid_till == datetime(2025, 1, 1)

    # Test RDS Describe DB Snapshots
    @mock_aws
    def test_describe_db_snapshots(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        conn.create_db_snapshot(
            DBInstanceIdentifier="db-primary-1", DBSnapshotIdentifier="snapshot-1"
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_snapshots) == 1
        assert rds.db_snapshots[0].id == "snapshot-1"
        assert rds.db_snapshots[0].instance_id == "db-primary-1"
        assert rds.db_snapshots[0].region == AWS_REGION_US_EAST_1
        assert not rds.db_snapshots[0].public

    # Test RDS Describe DB Clusters
    @mock_aws
    def test_describe_db_clusters(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        cluster_id = "db-master-1"
        conn.create_db_cluster_parameter_group(
            DBClusterParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            AllocatedStorage=10,
            Engine="postgres",
            DatabaseName="staging-postgres",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=False,
            AutoMinorVersionUpgrade=False,
            BackupRetentionPeriod=1,
            MasterUsername="test",
            MasterUserPassword="password",
            EnableCloudwatchLogsExports=["audit", "error"],
            DBClusterParameterGroupName="test",
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
            CopyTagsToSnapshot=True,
            Port=5432,
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)

        db_cluster_arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{cluster_id}"

        assert len(rds.db_clusters) == 1
        assert rds.db_clusters[db_cluster_arn].id == "db-master-1"
        assert rds.db_clusters[db_cluster_arn].engine == "postgres"
        assert rds.db_clusters[db_cluster_arn].region == AWS_REGION_US_EAST_1
        assert (
            f"{AWS_REGION_US_EAST_1}.rds.amazonaws.com"
            in rds.db_clusters[db_cluster_arn].endpoint
        )
        assert rds.db_clusters[db_cluster_arn].status == "available"
        assert not rds.db_clusters[db_cluster_arn].public
        assert rds.db_clusters[db_cluster_arn].encrypted
        assert rds.db_clusters[db_cluster_arn].backup_retention_period == 1
        assert rds.db_clusters[db_cluster_arn].cloudwatch_logs == ["audit", "error"]
        assert rds.db_clusters[db_cluster_arn].deletion_protection
        assert not rds.db_clusters[db_cluster_arn].auto_minor_version_upgrade
        assert not rds.db_clusters[db_cluster_arn].multi_az
        assert rds.db_clusters[db_cluster_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert rds.db_clusters[db_cluster_arn].parameter_group == "test"
        assert rds.db_clusters[db_cluster_arn].force_ssl == "0"
        assert rds.db_clusters[db_cluster_arn].require_secure_transport == "OFF"
        assert rds.db_clusters[db_cluster_arn].copy_tags_to_snapshot
        assert rds.db_clusters[db_cluster_arn].port == 5432

    # Test RDS Describe DB Cluster Snapshots
    @mock_aws
    def test_describe_db_cluster_snapshots(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_cluster(
            DBClusterIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBClusterInstanceClass="db.m1.small",
            MasterUsername="root",
            MasterUserPassword="hunter2000",
        )

        conn.create_db_cluster_snapshot(
            DBClusterIdentifier="db-primary-1", DBClusterSnapshotIdentifier="snapshot-1"
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_cluster_snapshots) == 1
        assert rds.db_cluster_snapshots[0].id == "snapshot-1"
        assert rds.db_cluster_snapshots[0].cluster_id == "db-primary-1"
        assert rds.db_cluster_snapshots[0].region == AWS_REGION_US_EAST_1
        assert not rds.db_cluster_snapshots[0].public

    # Test RDS describe db event subscriptions
    @mock_aws
    def test__describe_db_event_subscriptions_(self):
        # RDS client for this test class
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-security-group",
            Enabled=True,
            Tags=[
                {"Key": "test", "Value": "testing"},
            ],
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_event_subscriptions) == 1
        assert (
            rds.db_event_subscriptions[0].sns_topic_arn
            == f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test"
        )
        assert rds.db_event_subscriptions[0].enabled
        assert rds.db_event_subscriptions[0].region == AWS_REGION_US_EAST_1
        assert rds.db_event_subscriptions[0].source_type == "db-security-group"

    # Test RDS engine version
    @mock_aws
    def test_describe_db_engine_versions(self):
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert "mysql" in rds.db_engines[AWS_REGION_US_EAST_1]
        assert rds.db_engines[AWS_REGION_US_EAST_1]["mysql"].engine_versions == [
            "8.0.32"
        ]
        assert (
            rds.db_engines[AWS_REGION_US_EAST_1]["mysql"].engine_description
            == "description"
        )

    @mock_aws
    def test_list_tags(self):
        # RDS client for this test class
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-primary-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
        event_sub = conn.create_event_subscription(
            SubscriptionName="TestSub",
            SnsTopicArn=f"arn:aws:sns:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:test",
            SourceType="db-security-group",
            Enabled=True,
            Tags=[
                {"Key": "test", "Value": "testing"},
            ],
        )
        # Tag event subscription
        conn.add_tags_to_resource(
            ResourceName=event_sub["EventSubscription"]["EventSubscriptionArn"],
            Tags=[
                {"Key": "test", "Value": "testing"},
            ],
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_event_subscriptions) == 1
        assert rds.db_event_subscriptions[0].tags == [
            {"Key": "test", "Value": "testing"},
        ]
