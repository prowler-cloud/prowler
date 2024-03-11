from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.redshift.redshift_service import Redshift
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
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
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)
        assert redshift.service == "redshift"

    # Test Redshift client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)
        for reg_client in redshift.regional_clients.values():
            assert reg_client.__class__.__name__ == "Redshift"

    # Test Redshift session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)
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
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)

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
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)

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
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        redshift = Redshift(audit_info)

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
