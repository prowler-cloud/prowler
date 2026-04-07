from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_bedrock_vpc_endpoints_configured:
    @mock_aws
    def test_no_resources(self):
        """Test with no in-use VPCs and scan_unused_services disabled - should return no results."""
        client("ec2", region_name=AWS_REGION_US_EAST_1)

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_no_endpoints(self):
        """Test VPC with no VPC endpoints at all - should FAIL with both services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                assert len(result) == 1
                assert result[0].resource_id == vpc_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"VPC {vpc_id} does not have VPC endpoints for the following Bedrock services: Bedrock runtime, Bedrock agent runtime."
                )

    @mock_aws
    def test_vpc_only_bedrock_runtime_endpoint(self):
        """Test VPC with only Bedrock runtime endpoint - should FAIL with agent runtime missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-runtime",
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
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                # Find the result for the VPC we created
                for finding in result:
                    if finding.resource_id == vpc["VpcId"]:
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert finding.status == "FAIL"
                        assert (
                            finding.status_extended
                            == f"VPC {vpc['VpcId']} does not have VPC endpoints for the following Bedrock services: Bedrock agent runtime."
                        )
                        assert (
                            finding.resource_arn
                            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                        )

    @mock_aws
    def test_vpc_only_bedrock_agent_runtime_endpoint(self):
        """Test VPC with only Bedrock agent runtime endpoint - should FAIL with runtime missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-agent-runtime",
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
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                for finding in result:
                    if finding.resource_id == vpc["VpcId"]:
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert finding.status == "FAIL"
                        assert (
                            finding.status_extended
                            == f"VPC {vpc['VpcId']} does not have VPC endpoints for the following Bedrock services: Bedrock runtime."
                        )
                        assert (
                            finding.resource_arn
                            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                        )

    @mock_aws
    def test_vpc_both_bedrock_endpoints(self):
        """Test VPC with both Bedrock runtime and agent runtime endpoints - should PASS."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        vpc_default_id = ec2_client.describe_vpcs()["Vpcs"][0]["VpcId"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-runtime",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Interface",
        )
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.bedrock-agent-runtime",
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
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                # One VPC is created by default, so we should have 2 results
                assert len(result) == 2
                for finding in result:
                    if finding.resource_id == vpc["VpcId"]:
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert finding.status == "PASS"
                        assert (
                            finding.status_extended
                            == f"VPC {vpc['VpcId']} has VPC endpoints for both Bedrock runtime and Bedrock agent runtime services."
                        )
                        assert (
                            finding.resource_arn
                            == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc/{vpc['VpcId']}"
                        )
                    else:
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert finding.status == "FAIL"
                        assert (
                            finding.status_extended
                            == f"VPC {vpc_default_id} does not have VPC endpoints for the following Bedrock services: Bedrock runtime, Bedrock agent runtime."
                        )
                        assert finding.resource_id == vpc_default_id

    @mock_aws
    def test_vpc_unrelated_endpoint_only(self):
        """Test VPC with only an unrelated endpoint (S3) - should FAIL with both services missing."""
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
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
                "prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.bedrock.bedrock_vpc_endpoints_configured.bedrock_vpc_endpoints_configured import (
                    bedrock_vpc_endpoints_configured,
                )

                check = bedrock_vpc_endpoints_configured()
                result = check.execute()

                for finding in result:
                    if finding.resource_id == vpc["VpcId"]:
                        assert finding.region == AWS_REGION_US_EAST_1
                        assert finding.status == "FAIL"
                        assert (
                            finding.status_extended
                            == f"VPC {vpc['VpcId']} does not have VPC endpoints for the following Bedrock services: Bedrock runtime, Bedrock agent runtime."
                        )
