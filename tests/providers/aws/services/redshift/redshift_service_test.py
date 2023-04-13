from unittest.mock import patch
from uuid import uuid4

import botocore
from boto3 import client, session
from moto import mock_redshift

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.redshift.redshift_service import Redshift

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"

topic_name = "test-topic"
test_policy = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"{AWS_ACCOUNT_NUMBER}"},
            "Action": ["redshift:Publish"],
            "Resource": f"arn:aws:redshift:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:{topic_name}",
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


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.redshift.redshift_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Redshift_Service:
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

    # Test Redshift Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)
        assert redshift.service == "redshift"

    # Test Redshift client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)
        for reg_client in redshift.regional_clients.values():
            assert reg_client.__class__.__name__ == "Redshift"

    # Test Redshift session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)
        assert redshift.session.__class__.__name__ == "Session"

    @mock_redshift
    def test_describe_clusters(self):
        redshift_client = client("redshift", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION
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

    @mock_redshift
    def test_describe_logging_status(self):
        redshift_client = client("redshift", region_name=AWS_REGION)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
        )
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION
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

    @mock_redshift
    def test_describe_describe_cluster_snapshot(self):
        redshift_client = client("redshift", region_name=AWS_REGION)
        response = redshift_client.create_cluster(
            DBName="test",
            ClusterIdentifier=cluster_id,
            ClusterType="single-node",
            NodeType="ds2.xlarge",
            MasterUsername="user",
            MasterUserPassword="password",
            PubliclyAccessible=True,
        )
        audit_info = self.set_mocked_audit_info()
        redshift = Redshift(audit_info)

        assert len(redshift.clusters) == 1
        assert redshift.clusters[0].id == cluster_id
        assert redshift.clusters[0].region == AWS_REGION
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
