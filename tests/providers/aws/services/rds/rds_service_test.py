from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.rds.rds_service import RDS
from tests.providers.aws.audit_info_utils import (
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

    # Test Dynamo Service
    @mock_aws
    def test_service(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.service == "rds"

    # Test Dynamo Client
    @mock_aws
    def test_client(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        for regional_client in rds.regional_clients.values():
            assert regional_client.__class__.__name__ == "RDS"

    # Test Dynamo Session
    @mock_aws
    def test__get_session__(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.session.__class__.__name__ == "Session"

    # Test Dynamo Session
    @mock_aws
    def test_audited_account(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert rds.audited_account == AWS_ACCOUNT_NUMBER

    # Test RDS Describe DB Instances
    @mock_aws
    def test__describe_db_instances__(self):
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
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        # RDS client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rds = RDS(aws_provider)
        assert len(rds.db_instances) == 1
        assert rds.db_instances[0].id == "db-master-1"
        assert rds.db_instances[0].region == AWS_REGION_US_EAST_1
        assert (
            rds.db_instances[0].endpoint["Address"]
            == "db-master-1.aaaaaaaaaa.us-east-1.rds.amazonaws.com"
        )
        assert rds.db_instances[0].status == "available"
        assert rds.db_instances[0].public
        assert rds.db_instances[0].encrypted
        assert rds.db_instances[0].backup_retention_period == 10
        assert rds.db_instances[0].cloudwatch_logs == ["audit", "error"]
        assert rds.db_instances[0].deletion_protection
        assert rds.db_instances[0].auto_minor_version_upgrade
        assert rds.db_instances[0].multi_az
        assert rds.db_instances[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert "test" in rds.db_instances[0].parameter_groups

    @mock_aws
    def test__describe_db_parameters__(self):
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
        assert rds.db_instances[0].id == "db-master-1"
        assert rds.db_instances[0].region == AWS_REGION_US_EAST_1
        for parameter in rds.db_instances[0].parameters:
            if parameter["ParameterName"] == "rds.force_ssl":
                assert parameter["ParameterValue"] == "1"

    # Test RDS Describe DB Snapshots
    @mock_aws
    def test__describe_db_snapshots__(self):
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
    def test__describe_db_clusters__(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        cluster_id = "db-master-1"
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
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

    # Test RDS Describe DB Cluster Snapshots
    @mock_aws
    def test__describe_db_cluster_snapshots__(self):
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

    # Test RDS describe db engine versions
    @mock_aws
    def test__describe_db_engine_versions__(self):
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
