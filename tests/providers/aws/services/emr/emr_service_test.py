from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_emr

from prowler.providers.aws.services.emr.emr_service import EMR, ClusterStatus
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "GetBlockPublicAccessConfiguration":
        return {
            "BlockPublicAccessConfiguration": {
                "BlockPublicSecurityGroupRules": True,
                "PermittedPublicSecurityGroupRuleRanges": [
                    {"MinRange": 0, "MaxRange": 65535},
                ],
            },
            "BlockPublicAccessConfigurationMetadata": {
                "CreationDateTime": datetime(2015, 1, 1),
                "CreatedByArn": "test-arn",
            },
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_EMR_Service:
    # Test EMR Client
    @mock_emr
    def test__get_client__(self):
        emr = EMR(set_mocked_aws_audit_info())
        assert emr.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__ == "EMR"

    # Test EMR Session
    @mock_emr
    def test__get_session__(self):
        emr = EMR(set_mocked_aws_audit_info())
        assert emr.session.__class__.__name__ == "Session"

    # Test EMR Service
    @mock_emr
    def test__get_service__(self):
        emr = EMR(set_mocked_aws_audit_info())
        assert emr.service == "emr"

    # Test __list_clusters__ and __describe_cluster__
    @mock_emr
    def test__list_clusters__(self):
        # Create EMR Cluster
        emr_client = client("emr", region_name=AWS_REGION_EU_WEST_1)
        cluster_name = "test-cluster"
        run_job_flow_args = dict(
            Instances={
                "InstanceCount": 3,
                "KeepJobFlowAliveWhenNoSteps": True,
                "MasterInstanceType": "c3.medium",
                "Placement": {"AvailabilityZone": "us-east-1a"},
                "SlaveInstanceType": "c3.xlarge",
            },
            JobFlowRole="EMR_EC2_DefaultRole",
            LogUri="s3://mybucket/log",
            Name=cluster_name,
            ServiceRole="EMR_DefaultRole",
            VisibleToAllUsers=True,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        cluster_id = emr_client.run_job_flow(**run_job_flow_args)["JobFlowId"]
        # EMR Class
        emr = EMR(set_mocked_aws_audit_info())

        assert len(emr.clusters) == 1
        assert emr.clusters[cluster_id].id == cluster_id
        assert emr.clusters[cluster_id].name == cluster_name
        assert emr.clusters[cluster_id].status == ClusterStatus.WAITING
        assert (
            emr.clusters[cluster_id].arn
            == f"arn:aws:elasticmapreduce:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_id}"
        )
        assert emr.clusters[cluster_id].region == AWS_REGION_EU_WEST_1
        assert (
            emr.clusters[cluster_id].master_public_dns_name
            == "ec2-184-0-0-1.us-west-1.compute.amazonaws.com"
        )
        assert emr.clusters[cluster_id].public
        assert emr.clusters[cluster_id].tags == [
            {"Key": "test", "Value": "test"},
        ]

    @mock_emr
    def test__get_block_public_access_configuration__(self):
        emr = EMR(set_mocked_aws_audit_info())

        assert len(emr.block_public_access_configuration) == 1
        assert emr.block_public_access_configuration[
            AWS_REGION_EU_WEST_1
        ].block_public_security_group_rules
