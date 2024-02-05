from unittest import mock

from boto3 import client
from mock import MagicMock, patch
from moto import mock_aws

from prowler.providers.aws.services.neptune.neptune_service import Neptune
from prowler.providers.aws.services.vpc.vpc_service import VpcSubnet
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_audit_info,
)
from tests.providers.aws.services.neptune.neptune_service_test import (
    NEPTUNE_CLUSTER_NAME,
    NEPTUNE_CLUSTER_TAGS,
    NEPTUNE_ENGINE,
    SUBNET_1,
    SUBNET_2,
    mock_make_api_call,
)

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_neptune_cluster_uses_public_subnet:
    @mock_aws
    def test_neptune_no_clusters(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.neptune_client",
            new=Neptune(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet import (
                neptune_cluster_uses_public_subnet,
            )

            check = neptune_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_neptune_clusters_using_private_subnets(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}
        vpc_client.vpc_subnets[SUBNET_1] = VpcSubnet(
            id=SUBNET_1,
            arn="arn_test",
            name=SUBNET_1,
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.0/24",
            availability_zone=AWS_REGION_US_EAST_1_AZA,
            public=False,
            nat_gateway=False,
            region=AWS_REGION_US_EAST_1,
            tags=[],
            mapPublicIpOnLaunch=False,
        )
        vpc_client.vpc_subnets[SUBNET_2] = VpcSubnet(
            id=SUBNET_2,
            arn="arn_test",
            name=SUBNET_2,
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.1/24",
            availability_zone=AWS_REGION_US_EAST_1_AZB,
            public=False,
            nat_gateway=False,
            region=AWS_REGION_US_EAST_1,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

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
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.neptune_client",
            new=Neptune(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet import (
                neptune_cluster_uses_public_subnet,
            )

            check = neptune_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_id} is not using public subnets."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == NEPTUNE_CLUSTER_TAGS

    @mock_aws
    def test_neptune_clusters_using_public_subnets(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}
        vpc_client.vpc_subnets[SUBNET_1] = VpcSubnet(
            id=SUBNET_1,
            arn="arn_test",
            name=SUBNET_1,
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.0/24",
            availability_zone=AWS_REGION_US_EAST_1_AZA,
            public=True,
            nat_gateway=False,
            region=AWS_REGION_US_EAST_1,
            tags=[],
            mapPublicIpOnLaunch=False,
        )
        vpc_client.vpc_subnets[SUBNET_2] = VpcSubnet(
            id=SUBNET_2,
            arn="arn_test",
            name=SUBNET_2,
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.1/24",
            availability_zone=AWS_REGION_US_EAST_1_AZB,
            public=True,
            nat_gateway=False,
            region=AWS_REGION_US_EAST_1,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

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
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.neptune_client",
            new=Neptune(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet import (
                neptune_cluster_uses_public_subnet,
            )

            check = neptune_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_id} is using subnet-1, subnet-2 public subnets."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == NEPTUNE_CLUSTER_TAGS
