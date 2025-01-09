from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.redshift.redshift_service import Redshift
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

topic_name = "test-topic"
test_policy = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"{AWS_ACCOUNT_NUMBER}"},
            "Action": ["redshift:Publish"],
            "Resource": f"arn:aws:redshift:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
        }
    ]
}
test_bucket_name = "test-bucket"
cluster_id = str(uuid4())

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLoggingStatus":
        return {
            "LoggingEnabled": True,
            "BucketName": test_bucket_name,
        }
    if operation_name == "DescribeClusterSnapshots":
        return {
            "Snapshots": [
                {
                    "SnapshotIdentifier": uuid4(),
                },
            ]
        }
    if operation_name == "DescribeClusterParameters":
        return {
            "Parameters": [
                {
                    "ParameterName": "require_ssl",
                    "ParameterValue": "true",
                    "Description": "Require SSL for connections",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true, false",
                    "IsModifiable": True,
                    "MinimumEngineVersion": "1.0",
                },
            ]
        }

    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Redshift_Service:
    # Test Redshift Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)
        assert redshift.service == "redshift"

    # Test Redshift client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)
        for reg_client in redshift.regional_clients.values():
            assert reg_client.__class__.__name__ == "Redshift"

    # Test Redshift session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)
        assert redshift.session.__class__.__name__ == "Session"

    @mock_aws
    def test_describe_clusters(self):
        redshift_client = client("redshift", region_name=AWS_REGION_EU_WEST_1)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
            Encrypted=True,
            MultiAZ=False,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
            EnhancedVpcRouting=True,
            ClusterParameterGroupName="default.redshift-1.0",
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION_EU_WEST_1
        assert redshift.clusters[0].public_access
        assert redshift.clusters[0].vpc_id == response["Cluster"].get("VpcId")
        assert redshift.clusters[0].vpc_security_groups == [
            sg["VpcSecurityGroupId"]
            for sg in response["Cluster"]["VpcSecurityGroups"]
            if sg["Status"] == "active"
        ]
        assert (
            redshift.clusters[0].endpoint_address
            == response["Cluster"]["Endpoint"]["Address"]
        )
        assert (
            redshift.clusters[0].allow_version_upgrade
            == response["Cluster"]["AllowVersionUpgrade"]
        )
        assert redshift.clusters[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert redshift.clusters[0].parameter_group_name == "default.redshift-1.0"
        assert redshift.clusters[0].encrypted
        assert redshift.clusters[0].multi_az is False
        assert redshift.clusters[0].master_username == "user"
        assert redshift.clusters[0].enhanced_vpc_routing
        assert redshift.clusters[0].database_name == "test"

    @mock_aws
    def test_describe_logging_status(self):
        redshift_client = client("redshift", region_name=AWS_REGION_EU_WEST_1)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION_EU_WEST_1
        assert redshift.clusters[0].public_access
        assert (
            redshift.clusters[0].endpoint_address
            == response["Cluster"]["Endpoint"]["Address"]
        )
        assert (
            redshift.clusters[0].allow_version_upgrade
            == response["Cluster"]["AllowVersionUpgrade"]
        )
        assert redshift.clusters[0].logging_enabled
        assert redshift.clusters[0].bucket == test_bucket_name

    @mock_aws
    def test_describe_describe_cluster_snapshot(self):
        redshift_client = client("redshift", region_name=AWS_REGION_EU_WEST_1)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION_EU_WEST_1
        assert redshift.clusters[0].public_access
        assert (
            redshift.clusters[0].endpoint_address
            == response["Cluster"]["Endpoint"]["Address"]
        )
        assert (
            redshift.clusters[0].allow_version_upgrade
            == response["Cluster"]["AllowVersionUpgrade"]
        )
        assert redshift.clusters[0].logging_enabled
        assert redshift.clusters[0].bucket == test_bucket_name
        assert redshift.clusters[0].cluster_snapshots

    @mock_aws
    def test_describe_cluster_parameter_groups(self):
        redshift_client = client("redshift", region_name=AWS_REGION_EU_WEST_1)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION_EU_WEST_1
        assert redshift.clusters[0].public_access
        assert (
            redshift.clusters[0].endpoint_address
            == response["Cluster"]["Endpoint"]["Address"]
        )
        assert (
            redshift.clusters[0].allow_version_upgrade
            == response["Cluster"]["AllowVersionUpgrade"]
        )
        assert redshift.clusters[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert redshift.clusters[0].parameter_group_name == "default.redshift-1.0"
        assert redshift.clusters[0].require_ssl is True

    @mock_aws
    def test_describe_cluster_subnets(self):
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        subnet_id = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )["Subnet"]["SubnetId"]
        redshift_client = client("redshift", region_name=AWS_REGION_EU_WEST_1)
        redshift_client.create_cluster_subnet_group(
            ClusterSubnetGroupName="test-subnet",
            Description="Test Subnet",
            SubnetIds=[subnet_id],
        )
        _ = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
            VpcSecurityGroupIds=["sg-123456"],
            ClusterSubnetGroupName="test-subnet",
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        redshift = Redshift(aws_provider)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION_EU_WEST_1
        assert redshift.clusters[0].subnet_group == "test-subnet"
        assert redshift.clusters[0].subnets[0] == subnet_id
