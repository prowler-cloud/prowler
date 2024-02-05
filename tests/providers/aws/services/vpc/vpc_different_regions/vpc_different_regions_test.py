from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_vpc_different_regions:
    @mock_aws
    def test_no_vpcs(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions.vpc_client",
                new=VPC(current_audit_info),
            ) as vpc_client:
                # Remove all VPCs
                vpc_client.vpcs.clear()

                # Test Check
                from prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions import (
                    vpc_different_regions,
                )

                check = vpc_different_regions()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_different_regions(self):
        # VPC Region 1
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        # VPC Region 2
        ec2_client_eu = client("ec2", region_name="eu-west-1")
        ec2_client_eu.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions.vpc_client",
                new=VPC(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions import (
                    vpc_different_regions,
                )

                check = vpc_different_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].region == "us-east-1"
                assert (
                    result[0].status_extended == "VPCs found in more than one region."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].resource_tags == []

    @mock_aws
    def test_vpc_only_one_region(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # VPC Region 1
        ec2_client.create_vpc(CidrBlock="172.28.6.0/24", InstanceTenancy="default")

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions.vpc_client",
                new=VPC(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_different_regions.vpc_different_regions import (
                    vpc_different_regions,
                )

                check = vpc_different_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status_extended == "VPCs found only in one region."
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].resource_tags == []
