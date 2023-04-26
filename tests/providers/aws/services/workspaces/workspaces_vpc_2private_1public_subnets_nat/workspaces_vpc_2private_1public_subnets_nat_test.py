from unittest import mock
from moto import mock_ec2
from uuid import uuid4

from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpace

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
workspace_id = str(uuid4())
SUBNET_PUBLIC_ID = "subnet-1234567890"
SUBNET_PRIVATE_1_ID = "subnet-1234567891"
SUBNET_PRIVATE_2_ID = "subnet-1234567891"


class Test_workspaces_vpc_2private_1public_subnets_nat:
    def test_no_workspaces(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        vpc_client = mock.MagicMock
        vpc_client.vpcs = []
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                vpc_client,
            ):
                from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                    workspaces_vpc_2private_1public_subnets_nat,
                )

                check = workspaces_vpc_2private_1public_subnets_nat()
                result = check.execute()
                assert len(result) == 0

    @mock_ec2
    def test_workspaces_vpc_single_private_subnet(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=workspace_id,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id=SUBNET_PUBLIC_ID,
            )
        )
        vpc_client = mock.MagicMock
        vpc_client.vpcs = []
        vpc_client.vpc_subnets = []
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                vpc_client,
            ):
                from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                    workspaces_vpc_2private_1public_subnets_nat,
                )

                check = workspaces_vpc_2private_1public_subnets_nat()
                result = check.execute()
                assert len(result) == 1
