import botocore
from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.neptune.neptune_service import (
    Cluster,
    ClusterSnapshot,
    Neptune,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_provider,
)

SUBNET_GROUP_NAME = "default"
SUBNET_1 = "subnet-1"
SUBNET_2 = "subnet-2"

NEPTUNE_CLUSTER_NAME = "test-cluster"
NEPTUNE_ENGINE = "neptune"

NEPTUNE_CLUSTER_TAGS = [
    {"Key": "environment", "Value": "test"},
]

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeDBSubnetGroups":
        return {
            "DBSubnetGroups": [
                {
                    "DBSubnetGroupName": SUBNET_GROUP_NAME,
                    "DBSubnetGroupDescription": "Subnet Group",
                    "VpcId": "vpc-1",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-1",
                            "SubnetAvailabilityZone": {
                                "Name": AWS_REGION_US_EAST_1_AZA
                            },
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-2",
                            "SubnetAvailabilityZone": {
                                "Name": AWS_REGION_US_EAST_1_AZB
                            },
                            "SubnetStatus": "Active",
                        },
                    ],
                    "DBSubnetGroupArn": f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:subgrp:{SUBNET_GROUP_NAME}",
                }
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": NEPTUNE_CLUSTER_TAGS}

    if operation_name == "DescribeDBClusterSnapshots":
        return {
            "DBClusterSnapshots": [
                {
                    "DBClusterSnapshotIdentifier": "test-cluster-snapshot",
                    "DBClusterIdentifier": NEPTUNE_CLUSTER_NAME,
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
class Test_Neptune_Service:
    # Test Neptune Service
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        neptune = Neptune(aws_provider)
        assert neptune.service == "neptune"

    # Test Neptune Client]
    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        neptune = Neptune(aws_provider)
        assert neptune.client.__class__.__name__ == "Neptune"

    # Test Neptune Session
    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        neptune = Neptune(aws_provider)
        assert neptune.session.__class__.__name__ == "Session"

    # Test Neptune Session
    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        neptune = Neptune(aws_provider)
        assert neptune.audited_account == AWS_ACCOUNT_NUMBER

    # Test Neptune Get Neptune Contacts
    @mock_aws
    def test_describe_db_clusters(self):
        # Neptune client
        neptune_client = client("neptune", region_name=AWS_REGION_US_EAST_1)
        # Create Neptune Cluster
        cluster = neptune_client.create_db_cluster(
            AvailabilityZones=[AWS_REGION_US_EAST_1_AZA, AWS_REGION_US_EAST_1_AZB],
            BackupRetentionPeriod=1,
            CopyTagsToSnapshot=False,
            Engine=NEPTUNE_ENGINE,
            DatabaseName=NEPTUNE_CLUSTER_NAME,
            DBClusterIdentifier=NEPTUNE_CLUSTER_NAME,
            Port=123,
            StorageEncrypted=True,
            KmsKeyId="default_kms_key_id",
            Tags=NEPTUNE_CLUSTER_TAGS,
            EnableIAMDatabaseAuthentication=False,
            DeletionProtection=False,
        )["DBCluster"]

        cluster_arn = cluster["DBClusterArn"]
        cluster_id = cluster["DbClusterResourceId"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        neptune = Neptune(aws_provider)

        assert len(neptune.clusters) == 1
        assert neptune.clusters[cluster_arn]
        assert neptune.clusters[cluster_arn] == Cluster(
            arn=cluster_arn,
            name=NEPTUNE_CLUSTER_NAME,
            id=cluster_id,
            backup_retention_period=1,
            encrypted=True,
            kms_key="default_kms_key_id",
            multi_az=False,
            iam_auth=False,
            deletion_protection=False,
            region=AWS_REGION_US_EAST_1,
            db_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=NEPTUNE_CLUSTER_TAGS,
            copy_tags_to_snapshot=False,
            cloudwatch_logs=[],
        )

    def test_describe_db_cluster_snapshots(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        neptune = Neptune(aws_provider)

        expected_snapshot = ClusterSnapshot(
            id="test-cluster-snapshot",
            arn=f"arn:aws:neptune:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:test-cluster-snapshot",
            cluster_id=NEPTUNE_CLUSTER_NAME,
            encrypted=True,
            region=AWS_REGION_US_EAST_1,
            tags=[{"Key": "snapshot", "Value": "test"}],
        )

        neptune.db_cluster_snapshots = [expected_snapshot]

        assert neptune.db_cluster_snapshots[0] == expected_snapshot

    def test_describe_db_cluster_snapshot_attributes(self):
        aws_provider = set_mocked_aws_provider()
        neptune = Neptune(aws_provider)
        neptune.db_cluster_snapshots = [
            ClusterSnapshot(
                id="test-cluster-snapshot",
                arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster-snapshot:test-cluster-snapshot",
                cluster_id=NEPTUNE_CLUSTER_NAME,
                encrypted=True,
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "snapshot", "Value": "test"}],
            )
        ]
        neptune._describe_db_cluster_snapshot_attributes(
            neptune.regional_clients[AWS_REGION_US_EAST_1]
        )
        assert neptune.db_cluster_snapshots[0].public is True
