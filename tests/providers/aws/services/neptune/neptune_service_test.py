import botocore
from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.neptune.neptune_service import Cluster, Neptune
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_audit_info,
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
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        neptune = Neptune(audit_info)
        assert neptune.service == "neptune"

    # Test Neptune Client]
    @mock_aws
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        neptune = Neptune(audit_info)
        assert neptune.client.__class__.__name__ == "Neptune"

    # Test Neptune Session
    @mock_aws
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        neptune = Neptune(audit_info)
        assert neptune.session.__class__.__name__ == "Session"

    # Test Neptune Session
    @mock_aws
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        neptune = Neptune(audit_info)
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
            CopyTagsToSnapshot=True,
            Engine=NEPTUNE_ENGINE,
            DatabaseName=NEPTUNE_CLUSTER_NAME,
            DBClusterIdentifier=NEPTUNE_CLUSTER_NAME,
            Port=123,
            Tags=NEPTUNE_CLUSTER_TAGS,
            StorageEncrypted=False,
            DeletionProtection=True | False,
        )["DBCluster"]

        cluster_arn = cluster["DBClusterArn"]
        cluster_id = cluster["DbClusterResourceId"]

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        neptune = Neptune(audit_info)

        assert len(neptune.clusters) == 1
        assert neptune.clusters[cluster_arn]
        assert neptune.clusters[cluster_arn] == Cluster(
            arn=cluster_arn,
            name=NEPTUNE_CLUSTER_NAME,
            id=cluster_id,
            region=AWS_REGION_US_EAST_1,
            db_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=NEPTUNE_CLUSTER_TAGS,
        )
