from unittest import mock

from mock import MagicMock, patch
from moto import mock_aws

from prowler.providers.aws.services.elasticache.elasticache_service import Cluster
from prowler.providers.aws.services.vpc.vpc_service import VpcSubnet
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_audit_info,
)
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    ELASTICACHE_CLUSTER_ARN,
    ELASTICACHE_CLUSTER_NAME,
    ELASTICACHE_CLUSTER_TAGS,
    SUBNET_1,
    SUBNET_2,
    SUBNET_GROUP_NAME,
    mock_make_api_call,
)

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_elasticache_cluster_uses_public_subnet:
    @mock_aws
    def test_elasticache_no_clusters(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_cluster_uses_public_subnet.elasticache_cluster_uses_public_subnet import (
                elasticache_cluster_uses_public_subnet,
            )

            check = elasticache_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_clusters_using_private_subnets(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            region=AWS_REGION_US_EAST_1,
            cache_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=ELASTICACHE_CLUSTER_TAGS,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}
        vpc_client.vpc_subnets[SUBNET_1] = VpcSubnet(
            id=SUBNET_1,
            name=SUBNET_1,
            arn="arn_test",
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
            name=SUBNET_2,
            arn="arn_test",
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

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_cluster_uses_public_subnet.elasticache_cluster_uses_public_subnet import (
                elasticache_cluster_uses_public_subnet,
            )

            check = elasticache_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {ELASTICACHE_CLUSTER_NAME} is not using public subnets."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == ELASTICACHE_CLUSTER_NAME
            assert result[0].resource_arn == ELASTICACHE_CLUSTER_ARN
            assert result[0].resource_tags == ELASTICACHE_CLUSTER_TAGS

    def test_elasticache_clusters_using_public_subnets(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        elasticache_service.clusters[ELASTICACHE_CLUSTER_ARN] = Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            region=AWS_REGION_US_EAST_1,
            cache_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=ELASTICACHE_CLUSTER_TAGS,
        )

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}
        vpc_client.vpc_subnets[SUBNET_1] = VpcSubnet(
            id=SUBNET_1,
            name=SUBNET_1,
            arn="arn_test",
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
            name=SUBNET_2,
            arn="arn_test",
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

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_cluster_uses_public_subnet.elasticache_cluster_uses_public_subnet import (
                elasticache_cluster_uses_public_subnet,
            )

            check = elasticache_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {ELASTICACHE_CLUSTER_NAME} is using subnet-1, subnet-2 public subnets."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == ELASTICACHE_CLUSTER_NAME
            assert result[0].resource_arn == ELASTICACHE_CLUSTER_ARN
            assert result[0].resource_tags == ELASTICACHE_CLUSTER_TAGS
