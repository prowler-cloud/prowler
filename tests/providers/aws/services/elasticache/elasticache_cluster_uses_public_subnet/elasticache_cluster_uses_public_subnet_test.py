from unittest import mock

from boto3 import session
from mock import MagicMock, patch
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.elasticache.elasticache_service import Cluster
from prowler.providers.aws.services.vpc.vpc_service import VpcSubnet
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    AWS_REGION_AZ1,
    AWS_REGION_AZ2,
    ELASTICACHE_CLUSTER_ARN,
    ELASTICACHE_CLUSTER_NAME,
    ELASTICACHE_CLUSTER_TAGS,
    SUBNET_1,
    SUBNET_2,
    SUBNET_GROUP_NAME,
    mock_make_api_call,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_elasticache_cluster_uses_public_subnet:
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
            audited_regions=[AWS_REGION],
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

    @mock_ec2
    def test_elasticache_no_clusters(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.clusters = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
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
            region=AWS_REGION,
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
            availability_zone=AWS_REGION_AZ1,
            public=False,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )
        vpc_client.vpc_subnets[SUBNET_2] = VpcSubnet(
            id=SUBNET_2,
            name=SUBNET_1,
            arn="arn_test",
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.1/24",
            availability_zone=AWS_REGION_AZ2,
            public=False,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
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
            assert result[0].region == AWS_REGION
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
            region=AWS_REGION,
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
            availability_zone=AWS_REGION_AZ1,
            public=True,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )
        vpc_client.vpc_subnets[SUBNET_2] = VpcSubnet(
            id=SUBNET_2,
            name=SUBNET_1,
            arn="arn_test",
            default=False,
            vpc_id=VPC_ID,
            cidr_block="192.168.0.1/24",
            availability_zone=AWS_REGION_AZ2,
            public=True,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == ELASTICACHE_CLUSTER_NAME
            assert result[0].resource_arn == ELASTICACHE_CLUSTER_ARN
            assert result[0].resource_tags == ELASTICACHE_CLUSTER_TAGS
