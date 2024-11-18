import botocore
from mock import patch

from prowler.providers.aws.services.documentdb.documentdb_service import (
    ClusterSnapshot,
    DBCluster,
    DocumentDB,
    Instance,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DOC_DB_CLUSTER_ID = "test-cluster"
DOC_DB_INSTANCE_NAME = "test-db"
DOC_DB_INSTANCE_ARN = (
    f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{DOC_DB_INSTANCE_NAME}"
)
DOC_DB_CLUSTER_NAME = "test-cluster"
DOC_DB_CLUSTER_ARN = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{DOC_DB_CLUSTER_NAME}"
DOC_DB_ENGINE_VERSION = "5.0.0"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeDBInstances":
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": DOC_DB_INSTANCE_NAME,
                    "DBInstanceClass": "string",
                    "Engine": "docdb",
                    "DBInstanceStatus": "available",
                    "BackupRetentionPeriod": 1,
                    "EngineVersion": "5.0.0",
                    "AutoMinorVersionUpgrade": False,
                    "PubliclyAccessible": False,
                    "DBClusterIdentifier": DOC_DB_CLUSTER_ID,
                    "StorageEncrypted": False,
                    "DbiResourceId": "string",
                    "CACertificateIdentifier": "rds-ca-2015",
                    "CopyTagsToSnapshot": True | False,
                    "PromotionTier": 123,
                    "DBInstanceArn": DOC_DB_INSTANCE_ARN,
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": [{"Key": "environment", "Value": "test"}]}
    if operation_name == "DescribeDBClusters":
        return {
            "DBClusters": [
                {
                    "DBClusterIdentifier": DOC_DB_CLUSTER_ID,
                    "DBInstanceIdentifier": DOC_DB_CLUSTER_NAME,
                    "DBInstanceClass": "string",
                    "Engine": "docdb",
                    "Status": "available",
                    "BackupRetentionPeriod": 1,
                    "StorageEncrypted": False,
                    "EnabledCloudwatchLogsExports": [],
                    "DBClusterParameterGroupName": "test",
                    "DeletionProtection": True,
                    "MultiAZ": True,
                    "DBClusterParameterGroup": "default.docdb3.6",
                    "DBClusterArn": DOC_DB_CLUSTER_ARN,
                },
            ]
        }
    if operation_name == "DescribeDBClusterSnapshots":
        return {
            "DBClusterSnapshots": [
                {
                    "DBClusterSnapshotIdentifier": "test-cluster-snapshot",
                    "DBClusterIdentifier": DOC_DB_CLUSTER_ID,
                    "Engine": "docdb",
                    "Status": "available",
                    "StorageEncrypted": True,
                    "DBClusterSnapshotArn": f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:test-cluster-snapshot",
                    "TagList": [{"Key": "snapshot", "Value": "test"}],
                },
            ]
        }
    if operation_name == "DescribeDBClusterSnapshotAttributes":
        return {
            "DBClusterSnapshotAttributesResult": {
                "DBClusterSnapshotIdentifier": "test-cluster-snapshot",
                "DBClusterSnapshotAttributes": [
                    {"AttributeName": "restore", "AttributeValues": ["all"]}
                ],
            }
        }
    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DocumentDB_Service:
    # Test DocumentDB Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.service == "docdb"

    # Test DocumentDB Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.client.__class__.__name__ == "DocDB"

    # Test DocumentDB Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.session.__class__.__name__ == "Session"

    # Test DocumentDB Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.audited_account == AWS_ACCOUNT_NUMBER

    # Test DocumentDB Get DocumentDB Contacts
    def test_describe_db_instances(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.db_instances == {
            DOC_DB_INSTANCE_ARN: Instance(
                id=DOC_DB_INSTANCE_NAME,
                arn=DOC_DB_INSTANCE_ARN,
                engine="docdb",
                engine_version="5.0.0",
                status="available",
                public=False,
                encrypted=False,
                cluster_id=DOC_DB_CLUSTER_ID,
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "environment", "Value": "test"}],
            )
        }

    # Test DocumentDB Describe DB Clusters
    def test_describe_db_clusters(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.db_clusters == {
            DOC_DB_CLUSTER_ARN: DBCluster(
                id=DOC_DB_CLUSTER_NAME,
                arn=DOC_DB_CLUSTER_ARN,
                engine="docdb",
                status="available",
                backup_retention_period=1,
                encrypted=False,
                cloudwatch_logs=[],
                multi_az=True,
                parameter_group="default.docdb3.6",
                deletion_protection=True,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }

    # Test DocumentDB Describe DB Cluster Snapshots
    def test_describe_db_cluster_snapshots(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.db_cluster_snapshots == [
            ClusterSnapshot(
                id="test-cluster-snapshot",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:test-cluster-snapshot",
                cluster_id=DOC_DB_CLUSTER_ID,
                public=True,
                encrypted=True,
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "snapshot", "Value": "test"}],
            )
        ]

    # Test DocumentDB Describe DB Snapshot Attributes
    def test_describe_db_cluster_snapshot_attributes(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        docdb.db_cluster_snapshots = [
            ClusterSnapshot(
                id="test-cluster-snapshot",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:test-cluster-snapshot",
                cluster_id=DOC_DB_CLUSTER_ID,
                encrypted=True,
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "snapshot", "Value": "test"}],
            )
        ]
        docdb._describe_db_cluster_snapshot_attributes(
            docdb.regional_clients[AWS_REGION_US_EAST_1]
        )
        assert docdb.db_cluster_snapshots[0].public is True
