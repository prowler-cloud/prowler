from unittest import mock

from boto3 import client, session
from mock import MagicMock, patch
from moto import mock_ec2, mock_neptune

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.neptune.neptune_service import Neptune
from prowler.providers.aws.services.vpc.vpc_service import VpcSubnet
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.services.neptune.neptune_service_test import (
    AWS_REGION_AZ1,
    AWS_REGION_AZ2,
    NEPTUNE_CLUSTER_NAME,
    NEPTUNE_CLUSTER_TAGS,
    NEPTUNE_ENGINE,
    SUBNET_1,
    SUBNET_2,
    mock_make_api_call,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_neptune_cluster_uses_public_subnet:
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

    @mock_neptune
    @mock_ec2
    def test_neptune_no_clusters(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            return_value=Neptune(audit_info),
        ) as neptune_client, mock.patch(
            "prowler.providers.aws.services.neptune.neptune_client.neptune_client",
            neptune_client(),
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.neptune.neptune_cluster_uses_public_subnet.neptune_cluster_uses_public_subnet import (
                neptune_cluster_uses_public_subnet,
            )

            check = neptune_cluster_uses_public_subnet()
            result = check.execute()
            assert len(result) == 0

    @mock_neptune
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
            availability_zone=AWS_REGION_AZ1,
            public=False,
            nat_gateway=False,
            region=AWS_REGION,
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
            availability_zone=AWS_REGION_AZ2,
            public=False,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

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

        audit_info = self.set_mocked_audit_info()
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            return_value=Neptune(audit_info),
        ) as neptune_client, mock.patch(
            "prowler.providers.aws.services.neptune.neptune_client.neptune_client",
            new=neptune_client(),
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == NEPTUNE_CLUSTER_TAGS

    @mock_neptune
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
            availability_zone=AWS_REGION_AZ1,
            public=True,
            nat_gateway=False,
            region=AWS_REGION,
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
            availability_zone=AWS_REGION_AZ2,
            public=True,
            nat_gateway=False,
            region=AWS_REGION,
            tags=[],
            mapPublicIpOnLaunch=False,
        )

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

        audit_info = self.set_mocked_audit_info()
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.neptune.neptune_service.Neptune",
            return_value=Neptune(audit_info),
        ) as neptune_client, mock.patch(
            "prowler.providers.aws.services.neptune.neptune_client.neptune_client",
            new=neptune_client(),
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == cluster_arn
            assert result[0].resource_tags == NEPTUNE_CLUSTER_TAGS
