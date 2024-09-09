from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    set_mocked_aws_provider,
)


class Test_elbv2_is_in_multiple_az:
    @mock_aws
    def test_no_elbs(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az.elbv2_client",
            new=ELBv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az import (
                elbv2_is_in_multiple_az,
            )

            check = elbv2_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elbv2_in_one_avaibility_zone(self):
        # Create VPC, Subnets and Security Group
        elbv2_client = client("elbv2", region_name=AWS_REGION_EU_WEST_1)

        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")

        subnet1 = ec2.create_subnet(
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
            CidrBlock="10.0.1.0/24",
            VpcId=vpc.id,
        )

        lb_arn = elbv2_client.create_load_balancer(
            Name="test_elbv2",
            Subnets=[subnet1.id],
            SecurityGroups=[security_group.id],
        )["LoadBalancers"][0]["LoadBalancerArn"]

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az.elbv2_client",
            new=ELBv2(aws_provider),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az import (
                elbv2_is_in_multiple_az,
            )

            check = elbv2_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ELBv2 test_elbv2 is not in at least 2 AZs. Is only in {AWS_REGION_EU_WEST_1_AZA}."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "test_elbv2"
            assert result[0].resource_arn == lb_arn
            assert result[0].resource_tags == []

    @mock_aws
    def test_elbv2_in_two_avaibility_zones(self):
        # Create VPC, Subnets and Security Group
        elbv2_client = client("elbv2", region_name=AWS_REGION_EU_WEST_1)

        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")

        subnet1 = ec2.create_subnet(
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
            CidrBlock="10.0.1.0/24",
            VpcId=vpc.id,
        )

        subnet2 = ec2.create_subnet(
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
            CidrBlock="10.0.2.0/24",
            VpcId=vpc.id,
        )

        lb_arn = elbv2_client.create_load_balancer(
            Name="test_elbv2",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
        )["LoadBalancers"][0]["LoadBalancerArn"]

        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az.elbv2_client",
            new=ELBv2(aws_provider),
        ):
            from prowler.providers.aws.services.elbv2.elbv2_is_in_multiple_az.elbv2_is_in_multiple_az import (
                elbv2_is_in_multiple_az,
            )

            check = elbv2_is_in_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ELBv2 test_elbv2 is at least in 2 AZs: {AWS_REGION_EU_WEST_1_AZA}, {AWS_REGION_EU_WEST_1_AZB}."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == "test_elbv2"
            assert result[0].resource_arn == lb_arn
            assert result[0].resource_tags == []
