import botocore
from boto3 import client, session
from mock import patch
from moto import mock_neptune

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.neptune.neptune_service import Cluster, Neptune
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

AWS_REGION = "us-east-1"
AWS_REGION_AZ1 = "us-east-1a"
AWS_REGION_AZ2 = "us-east-b"

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
                            "SubnetAvailabilityZone": {"Name": AWS_REGION_AZ1},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-2",
                            "SubnetAvailabilityZone": {"Name": AWS_REGION_AZ2},
                            "SubnetStatus": "Active",
                        },
                    ],
                    "DBSubnetGroupArn": f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:subgrp:{SUBNET_GROUP_NAME}",
                }
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": NEPTUNE_CLUSTER_TAGS}

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Neptune_Service:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test Neptune Service
    @mock_neptune
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        neptune = Neptune(audit_info)
        assert neptune.service == "neptune"

    # Test Neptune Client]
    @mock_neptune
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        neptune = Neptune(audit_info)
        assert neptune.client.__class__.__name__ == "Neptune"

    # Test Neptune Session
    @mock_neptune
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        neptune = Neptune(audit_info)
        assert neptune.session.__class__.__name__ == "Session"

    # Test Neptune Session
    @mock_neptune
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        neptune = Neptune(audit_info)
        assert neptune.audited_account == AWS_ACCOUNT_NUMBER

    # Test Neptune Get Neptune Contacts
    @mock_neptune
    def test_describe_db_clusters(self):
        # Neptune client
        neptune_client = client("neptune", region_name=AWS_REGION)
        # Create Neptune Cluster
        cluster = neptune_client.create_db_cluster(
            AvailabilityZones=[AWS_REGION_AZ1, AWS_REGION_AZ2],
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        neptune = Neptune(audit_info)

        assert len(neptune.clusters) == 1
        assert neptune.clusters[cluster_arn]
        assert neptune.clusters[cluster_arn] == Cluster(
            arn=cluster_arn,
            name=NEPTUNE_CLUSTER_NAME,
            id=cluster_id,
            region=AWS_REGION,
            db_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=NEPTUNE_CLUSTER_TAGS,
        )
