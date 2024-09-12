from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_vpc_endpoint_for_ec2_enabled:
    @mock_aws
    def test_vpc_no_endpoints(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled import (
                    vpc_endpoint_for_ec2_enabled,
                )

                check = vpc_endpoint_for_ec2_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].resource_id == vpc_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == f"VPC {vpc_id} has no EC2 endpoint."

    @mock_aws
    def test_vpc_no_ec2_endpoint(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        vpc_default_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.vpce.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled import (
                    vpc_endpoint_for_ec2_enabled,
                )

                check = vpc_endpoint_for_ec2_enabled()
                result = check.execute()

                # One VPC is created by default, so we should have 2 results
                assert len(result) == 2
                for result_vpc in result:
                    if result_vpc.resource_id == vpc["VpcId"]:
                        assert result_vpc.region == AWS_REGION_US_EAST_1
                        assert result_vpc.status == "FAIL"
                        assert (
                            result_vpc.status_extended
                            == f"VPC {vpc['VpcId']} has no EC2 endpoint."
                        )
                        assert (
                            result_vpc.resource_arn
                            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                        )
                    else:
                        assert result_vpc.region == AWS_REGION_US_EAST_1
                        assert result_vpc.status == "FAIL"
                        assert (
                            result_vpc.status_extended
                            == f"VPC {vpc_default_id} has no EC2 endpoint."
                        )
                        assert result_vpc.resource_id == vpc_default_id

    @mock_aws
    def test_vpc_ec2_endpoint_enabled(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        vpc_default_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.vpce.us-east-1.ec2",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_for_ec2_enabled.vpc_endpoint_for_ec2_enabled import (
                    vpc_endpoint_for_ec2_enabled,
                )

                check = vpc_endpoint_for_ec2_enabled()
                result = check.execute()

                # One VPC is created by default, so we should have 2 results
                assert len(result) == 2
                for result_vpc in result:
                    if result_vpc.resource_id == vpc["VpcId"]:
                        assert result_vpc.region == AWS_REGION_US_EAST_1
                        assert result_vpc.status == "PASS"
                        assert (
                            result_vpc.status_extended
                            == f"VPC {vpc['VpcId']} has an EC2 Gateway endpoint."
                        )
                        assert (
                            result_vpc.resource_arn
                            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                        )
                    else:
                        assert result_vpc.region == AWS_REGION_US_EAST_1
                        assert result_vpc.status == "FAIL"
                        assert (
                            result_vpc.status_extended
                            == f"VPC {vpc_default_id} has no EC2 endpoint."
                        )
                        assert result_vpc.resource_id == vpc_default_id
