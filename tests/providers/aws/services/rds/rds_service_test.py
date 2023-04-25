from boto3 import client, session
from moto import mock_rds

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.rds.rds_service import RDS

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_RDS_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test Dynamo Service
    @mock_rds
    def test_service(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert rds.service == "rds"

    # Test Dynamo Client
    @mock_rds
    def test_client(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        for regional_client in rds.regional_clients.values():
            assert regional_client.__class__.__name__ == "RDS"

    # Test Dynamo Session
    @mock_rds
    def test__get_session__(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert rds.session.__class__.__name__ == "Session"

    # Test Dynamo Session
    @mock_rds
    def test_audited_account(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert rds.audited_account == AWS_ACCOUNT_NUMBER

    # Test RDS Describe DB Instances
    @mock_rds
    def test__describe_db_instances__(self):
        conn = client("rds", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert len(rds.db_instances) == 1
        assert rds.db_instances[0].id == "db-master-1"
        assert rds.db_instances[0].region == AWS_REGION
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

    @mock_rds
    def test__describe_db_parameters__(self):
        conn = client("rds", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert len(rds.db_instances) == 1
        assert rds.db_instances[0].id == "db-master-1"
        assert rds.db_instances[0].region == AWS_REGION
        for parameter in rds.db_instances[0].parameters:
            if parameter["ParameterName"] == "rds.force_ssl":
                assert parameter["ParameterValue"] == "1"

    # Test RDS Describe DB Snapshots
    @mock_rds
    def test__describe_db_snapshots__(self):
        conn = client("rds", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert len(rds.db_snapshots) == 1
        assert rds.db_snapshots[0].id == "snapshot-1"
        assert rds.db_snapshots[0].instance_id == "db-primary-1"
        assert rds.db_snapshots[0].region == AWS_REGION
        assert not rds.db_snapshots[0].public

    # Test RDS Describe DB Clusters
    @mock_rds
    def test__describe_db_clusters__(self):
        conn = client("rds", region_name=AWS_REGION)
        conn.create_db_parameter_group(
            DBParameterGroupName="test",
            DBParameterGroupFamily="default.postgres9.3",
            Description="test parameter group",
        )
        conn.create_db_cluster(
            DBClusterIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DatabaseName="staging-postgres",
            StorageEncrypted=False,
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
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert len(rds.db_clusters) == 1
        assert rds.db_clusters[0].id == "db-master-1"
        assert rds.db_clusters[0].region == AWS_REGION
        assert "us-east-1.rds.amazonaws.com" in rds.db_clusters[0].endpoint
        assert rds.db_clusters[0].status == "available"
        assert not rds.db_clusters[0].public
        assert not rds.db_clusters[0].encrypted
        assert rds.db_clusters[0].backup_retention_period == 1
        assert rds.db_clusters[0].cloudwatch_logs == ["audit", "error"]
        assert rds.db_clusters[0].deletion_protection
        assert not rds.db_clusters[0].auto_minor_version_upgrade
        assert not rds.db_clusters[0].multi_az
        assert rds.db_clusters[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert rds.db_clusters[0].parameter_group == "test"

    # Test RDS Describe DB Cluster Snapshots
    @mock_rds
    def test__describe_db_cluster_snapshots__(self):
        conn = client("rds", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        rds = RDS(audit_info)
        assert len(rds.db_cluster_snapshots) == 1
        assert rds.db_cluster_snapshots[0].id == "snapshot-1"
        assert rds.db_cluster_snapshots[0].cluster_id == "db-primary-1"
        assert rds.db_cluster_snapshots[0].region == AWS_REGION
        assert not rds.db_cluster_snapshots[0].public
